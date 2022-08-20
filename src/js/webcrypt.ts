// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


import {send_command} from "./transport";
import {WEBCRYPT_CMD, string_to_errcode, VERBOSE} from "./constants";
import {CommandExecutionError} from "./exceptions";
import {delay} from "@/js/helpers";
import {Session} from "@/js/session";
import {log_fn} from "@/js/logs";
import {Dictionary, StatusCallback, WCKeyDetails} from "@/js/types";

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
