// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


import {send_command} from "./transport";
import {string_to_errcode, VERBOSE, WEBCRYPT_CMD} from "./constants";
import {CommandExecutionError} from "./exceptions";
import {
    agree_on_key,
    buffer_to_uint8,
    byteToHexString,
    calculate_hmac,
    delay,
    ecdsa_to_ecdh,
    encode_text,
    encrypt_aes,
    export_key,
    flatten,
    generate_key_ecc,
    hexStringToByte,
    import_key,
    number_to_short,
    pkcs7_pad_16
} from "@/js/helpers";
import {Session} from "@/js/session";
import {log_fn} from "@/js/logs";
import {Dictionary, StatusCallback, WCKeyDetails} from "@/js/types";
import {CommandDecryptParams} from "@/js/commands";

export * from "@/js/commands";

const session = new Session();

/**
 * @deprecated
 */
export async function WEBCRYPT_STATUS(statusCallback: StatusCallback): Promise<Dictionary> {
    return await send_command(session, WEBCRYPT_CMD.STATUS, {}, statusCallback);
}

// TODO move to repeat_wrapper
/**
 * @deprecated
 */
export async function WEBCRYPT_LOGIN(PIN: string, statusCallback: StatusCallback) {
    const data = { 'PIN': PIN };
    let result: any = {};
    let err: any = 0;
    const total_attempts = 5;
    for (let i = 0; i < total_attempts; i++) {
        try {
            if (VERBOSE) console.log('Please press the touch button to continue');
            await log_fn(`Login attempt: ${i+1}/${total_attempts}`);
            result = await send_command(session, WEBCRYPT_CMD.LOGIN, data, statusCallback);
            err = 0;
            break;
        } catch (error) {

            if (error instanceof CommandExecutionError && i < total_attempts-1) {
                // error: CommandExecutionError;
                if (error.errcode !== string_to_errcode['ERR_USER_NOT_PRESENT']) {
                    await log_fn(`Error encountered: ${error.name}`);
                    throw error;
                }
                if (VERBOSE) console.log('error', error);
                err = error;
                await delay(1000);
                await log_fn('User touch not registered. Trying to log in one more time.');
            } else {
                throw error;
            }

        }
    }
    if (err) {
        await log_fn('User touch not registered. Throwing exception.');
        throw err;
    }
    session.token = result['TP'];
    await log_fn('User touch registered. Logged in.');
}


/**
 * @deprecated
 */
export async function WEBCRYPT_GENERATE_FROM_DATA(statusCallback: StatusCallback, data: Uint8Array): Promise<WCKeyDetails> {
    const data_to_send = {'HASH': data};
    try {
        const res = await send_command(session, WEBCRYPT_CMD.GENERATE_KEY_FROM_DATA, data_to_send, statusCallback);
        const pk: string = res["PUBKEY"];
        return new WCKeyDetails(pk, res["KEYHANDLE"]);
    } catch (e) {
        console.log(e);
    }
    return new WCKeyDetails("", "");
}

/**
 * @deprecated
 */
export async function WEBCRYPT_GENERATE(statusCallback: StatusCallback): Promise<WCKeyDetails> {
    const res = await send_command(session, WEBCRYPT_CMD.GENERATE_KEY, null, statusCallback);
    const pk: string = res["PUBKEY"];
    return new WCKeyDetails(pk, res["KEYHANDLE"]);
}

/**
 * @deprecated
 */
export async function WEBCRYPT_SIGN(statusCallback: StatusCallback, hash: Uint8Array, key_handle: Uint8Array): Promise<string> {
    const data_to_send = {'HASH': hash, 'KEYHANDLE': key_handle};
    const res = await send_command(session, WEBCRYPT_CMD.SIGN, data_to_send, statusCallback);
    return res["SIGNATURE"];
}

export async function WEBCRYPT_ENCRYPT(statusCallback: StatusCallback, data_to_encrypt: string, pubkey_hex: string, keyhandle_hex: string): Promise<CommandDecryptParams> {
    // 1. Generate ECC key
    // 2. Agree on a shared secret with the keyhandle's public key
    // 3. Encrypt data with the shared secret AES-256
    // 4. Calculate HMAC
    // 5. Pack it or provide in separate fields.

    // TODO accept uint8array type for encryption as well
    const plaintext = await encode_text(data_to_encrypt);
    const plaintext_with_len = flatten([buffer_to_uint8(await number_to_short(plaintext.length)), plaintext]);
    const plaintext_pad = pkcs7_pad_16(plaintext_with_len);
    const pubkey_raw = hexStringToByte(pubkey_hex);
    const pubkey = await import_key(pubkey_raw); // TODO import directly as ECDH, without usages
    const pubkey_ecdh = await ecdsa_to_ecdh(pubkey);
    const keyhandle = hexStringToByte(keyhandle_hex);
    const ephereal_keypair = await generate_key_ecc();
    const ephereal_pubkey = ephereal_keypair.publicKey;
    const ephereal_pubkey_raw = await export_key(ephereal_pubkey);
    const aes_key = await agree_on_key(ephereal_keypair.privateKey, pubkey_ecdh);
    const ciphertext = await encrypt_aes(aes_key, plaintext_pad);
    const ciphertext_len = await number_to_short(ciphertext.byteLength);
    // TODO: DESIGN derive different keys for hmac and encryption
    const data_to_hmac = flatten([buffer_to_uint8(ciphertext), ephereal_pubkey_raw,
        buffer_to_uint8(ciphertext_len), keyhandle]);
    const hmac = await calculate_hmac(aes_key, data_to_hmac);

    return new CommandDecryptParams(
        byteToHexString(buffer_to_uint8(ciphertext)),
        byteToHexString(keyhandle),
        byteToHexString(buffer_to_uint8(hmac)),
        byteToHexString(ephereal_pubkey_raw)
    );
}

export async function WEBCRYPT_VERIFY(statusCallback: StatusCallback, pubkey_hex: string, signature_hex: string, hash_hex: string): Promise<boolean> {
    const algorithm = {
        name: "ECDSA",
        hash: {name: "SHA-256"},
        namedCurve: "P-256",
    };
    try {
        const publicKey = await crypto.subtle.importKey(
            'raw',
            hexStringToByte(pubkey_hex),
            algorithm,
            true,
            ["verify"]
        );

        const signature = hexStringToByte(signature_hex);
        const encoded = hexStringToByte(hash_hex);

        return await window.crypto.subtle.verify(
            algorithm,
            publicKey,
            signature,
            encoded
        );
    } catch (e) {
        console.log('fail', e);
        return false;
    }
}
