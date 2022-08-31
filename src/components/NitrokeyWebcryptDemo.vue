<template>
  <div class="hello">
    <h1>{{ msg }}</h1>

    <p></p>


    <b-container fluid="md">
      <div>
        <!--      model -->
        <div>
          <b-form-group
              id="fieldset-3"
              description="Public key to be sent to the recipient"
              label="Key seed"
              label-for="input-3"
              valid-feedback="Thank you!"
          >
            <b-form-input id="input-3" v-model="KEYSEED" placeholder="Enter data after which a key will be generated, e.g. passphrase" trim ></b-form-input>
            <b-form-input id="input-4" v-model="keyseedHash" placeholder="KEYSEED" trim ></b-form-input>
            <button @click="generateKeyFromData" :disabled="!logged_in">GENERATE KEY FROM SEED</button>
          </b-form-group>

          <b-form-group
              id="fieldset-1"
              description="Current key data"
              label="Keyhandle for the internal use"
              label-for="input-1"
              valid-feedback="Correct keyhandle"
              :state="state"
          >
            <b-form-input id="input-1" v-model="KEYHANDLE" :state="state" placeholder="KEYHANDLE" trim disabled></b-form-input>
          </b-form-group>

          <b-form-group
              id="fieldset-2"
              description="Public key to be sent to the recipient"
              label="Public key for this Keyhandle"
              label-for="input-2"
              valid-feedback="Thank you!"
          >
            <b-form-input id="input-2" v-model="PUBKEY" placeholder="PUBKEY" trim disabled></b-form-input>
          </b-form-group>


        </div>

        <button @click="login">RESET AND LOGIN</button>
        <button @click="logout" :disabled="!logged_in">LOGOUT</button>
        <button @click="generateKey" :disabled="!logged_in">GENERATE KEY</button>
        <button @click="WebcryptTests">TEST</button>

      </div>

      <div>
        <b-tabs content-class="mt-3" v-model="active_tab">
          <b-tab title="Sign" active>
            <p>Here you can sign data</p>

            <b-form-input v-model="text" placeholder="Enter data to hash and sign"></b-form-input>
            <b-form-input v-model="hash" placeholder="Calculated hash" disabled></b-form-input>
            <b-form-input v-model="signature" placeholder="Signature" disabled></b-form-input>
            <b-form-input v-model="SignatureVerified" placeholder="Signature verified?" disabled></b-form-input>
            <button @click="signData" :disabled="!logged_in || !KEYHANDLE">SIGN DATA</button>

          </b-tab>
          <b-tab title="Encrypt">
            <p>Data encryption</p>

            <b-form-input v-model="encryptText" placeholder="Enter data to encrypt"></b-form-input>
            <b-form-input v-model="encryptTextResult" placeholder="Here will be encryption result"></b-form-input>
            <button @click="encryptData" :disabled="!KEYHANDLE">ENCRYPT DATA</button>

          </b-tab>
          <b-tab title="Decrypt">
            <p>Data decryption</p>

            <b-form-input v-model="decryptText" placeholder="Enter data to decrypt"></b-form-input>
            <button @click="decryptData" :disabled="!logged_in || !KEYHANDLE">DECRYPT DATA</button>


          </b-tab>
          <!--          <b-tab title="Test"><p>Test and status</p></b-tab>-->

          <b-tab title="Custom">
            <p>Custom commands</p>
            <b-form id="custom_cmd_form" @submit="execute_custom_command" @submit.stop.prevent>
              <b-form-select v-model="selected" :options="commands"/>

              <div v-for="p of params">
                <b-form-input :placeholder=p.placeholder :name=p.name
                              v-model="custom_cmd_form[p.name]"></b-form-input>
              </div>
<!--            <button @click="execute_custom_command">Execute</button>-->
              <b-button type="submit" variant="primary">Execute</b-button>
            </b-form>
            <div style="word-wrap: anywhere; text-align: center; position: center">
              Parameters: {{ JSON.stringify(custom_cmd_form) }}
            </div>
            <div style="word-wrap: anywhere; text-align: center; position: center">
              Reply: {{custom_cmd_form_reply}}
            </div>
          </b-tab>

          <b-tab title="Console">
            <p>Console data</p>

            <!--            <b-progress :value="value" :max="max" show-progress animated></b-progress>-->
            <button @click="clear_console">Clear</button>
            <b-progress-bar v-model="progress.value" :max="progress.max" variant="success" show-progress show-value></b-progress-bar>
            <b-form-textarea
                id="console"
                placeholder="Enter something..."
                v-model="console"
                rows="3"
                max-rows="12"
            ></b-form-textarea>

          </b-tab>
        </b-tabs>
      </div>
    </b-container>


  </div>
</template>

<script lang="ts">
import {Component, Prop, Vue} from 'vue-property-decorator';
import {
  CommandLoginParams,
  CommandSetPinParams,
  Webcrypt_FactoryReset,
  WEBCRYPT_GENERATE,
  WEBCRYPT_GENERATE_FROM_DATA,
  Webcrypt_Login,
  Webcrypt_Logout,
  Webcrypt_SetPin,
  WEBCRYPT_SIGN,
} from "@/js/webcrypt";
import {
  agree_on_key, buffer_to_uint8,
  byteToHexString, calculate_hmac,
  clone_object,
  dict_binval,
  dict_empty,
  dict_hexval, encode_text, encrypt_aes, export_key, flatten,
  generate_key_ecc,
  hexStringToByte, import_key,
  keys, number_to_short
} from "@/js/helpers";
import {sha256} from "js-sha256";
import {send_command} from "@/js/transport";
import {commands_parameters, string_to_command} from "@/js/constants";
import {Session} from "@/js/session";
import {Dictionary} from "@/js/types";
import {log_fn} from "@/js/logs";
import {WebcryptTests} from "@/js/tests";


function keys_to_options(keys_list: any): any {
  let a = [];
  a.push(Object.freeze({value: null, text: 'Please select an option'}));
  for (const k in keys_list) {
    const s = keys_list[k];
    a.push(Object.freeze({value: s, text: s}));
  }
  // console.log(a);
  return a;
}

@Component
export default class NitrokeyWebcryptDemo extends Vue {
  @Prop() private msg!: string;

  text = "";
  // hash = "";
  hashU8 = new Uint8Array(32);
  signature = "";
  console = "";
  KEYHANDLE = "";
  PUBKEY = "";
  KEYSEED = "";
  KEYSEEDHASH = "";
  selected = "STATUS";
  commands = keys_to_options(keys(commands_parameters));
  custom_cmd_form = {};
  custom_cmd_form_reply = "";
  active_tab = 0;
  progress = {value: 0, max: 100};
  logged_in = "";
  encryptText = "";
  encryptTextResult = "";
  decryptText = "";

  get params() {
    if (this.selected === null) {
      return [];
    }
    this.custom_cmd_form = {};
    const p = commands_parameters[this.selected];
    let res = [];
    for (const pKey in p) {
      const a = {
        name: pKey,
        type: p[pKey],
        placeholder: `${pKey}:${p[pKey]}`
      }
      res.push(a);
    }
    // console.log(p, res);
    return res;
  }

  get hash() {
    this.hashU8 = hexStringToByte(sha256(this.text));
    return byteToHexString(this.hashU8);
  }

  get keyseedHash(){
    this.KEYSEEDHASH = sha256(this.KEYSEED);
    return this.KEYSEEDHASH;
  }

  async clear_console() {
    this.console = "";
  }

  async verify(): Promise<boolean> {
    const algorithm = {
      name: "ECDSA",
      hash: {name: "SHA-256"},
      namedCurve: "P-256",
    };

    try {
      const publicKey = await crypto.subtle.importKey(
          'raw',
          hexStringToByte(this.PUBKEY),
          algorithm,
          true,
          ["verify"]
      );

      const signature = hexStringToByte(this.signature);
      const encoded = hexStringToByte(this.hash);

      const result = await window.crypto.subtle.verify(
          algorithm,
          publicKey,
          signature,
          encoded
      );
      console.log("verify result", result);

      return result;
    } catch (e) {
      console.log('fail', e);
      return false;
      // throw e;
    }
    // eslint-disable-next-line no-unreachable
    return false;
  }

  get SignatureVerified() {
    if (this.signature == "") {
      return "not verified";
    }

    if (this.verify()) {
      return "verified!";
    }

    return "not verified";
  }

  get state(){
    // when it passed validation
    return this.KEYHANDLE != "";
    // return false;
  }


  async log_console(s: string): Promise<void> {
    console.log(s);
    this.console += `${s}\n`
    return Promise.resolve();
  }

  async generateKey(): Promise<void> {
    const genkey = await WEBCRYPT_GENERATE(this.log_console);
    this.KEYHANDLE = genkey.keyhandle;
    this.PUBKEY = genkey.pubkey;
  }

  async login(): Promise<void> {
    await Webcrypt_FactoryReset(this.log_console);
    await Webcrypt_SetPin(this.log_console, new CommandSetPinParams('123123'));
    const res = await Webcrypt_Login(this.log_console, new CommandLoginParams('123123'));
    this.logged_in = res.TP;
  }

  async logout(): Promise<void> {
    await Webcrypt_Logout(this.log_console);
    this.logged_in = "";
  }

  async generateKeyFromData(): Promise<void> {
    const data = hexStringToByte(sha256(this.KEYSEED));
    const genkey = await WEBCRYPT_GENERATE_FROM_DATA(this.log_console, data);
    this.KEYHANDLE = genkey.keyhandle;
    this.PUBKEY = genkey.pubkey;
  }

  async signData(): Promise<void> {
    const sign = await WEBCRYPT_SIGN(this.log_console, this.hashU8, hexStringToByte(this.KEYHANDLE));
    this.signature = sign;
  }

  async encryptData(): Promise<void> {
    // const publicKey = await crypto.subtle.importKey();
    // 1. Generate ECC key
    // 2. Agree on a shared secret with the keyhandle's public key
    // 3. Encrypt data with the shared secret AES-256
    // 4. Calculate HMAC
    // 5. Pack it or provide in separate fields.

    const plaintext = await encode_text(this.encryptText);
    const pubkey_raw = hexStringToByte(this.PUBKEY);
    const pubkey = await import_key(pubkey_raw);
    const keyhandle = hexStringToByte(this.KEYHANDLE);
    const ephereal_keypair = await generate_key_ecc();
    const ephereal_pubkey = ephereal_keypair.publicKey;
    const ephereal_pubkey_raw = await export_key(ephereal_pubkey);
    const aes_key = await agree_on_key(ephereal_keypair.privateKey, pubkey);
    const ciphertext = await encrypt_aes(aes_key, plaintext);
    const ciphertext_len = await number_to_short(ciphertext.byteLength);
    // TODO: DESIGN derive different keys for hmac and encryption
    const hmac = await calculate_hmac(ephereal_keypair.privateKey,
        flatten([buffer_to_uint8(ciphertext), ephereal_pubkey_raw,
          buffer_to_uint8(ciphertext_len), keyhandle])
    );

    const result = {
      DATA: ciphertext,
      KEYHANDLE: keyhandle,
      HMAC: hmac,
      ECCEKEY: ephereal_pubkey_raw
    };

    this.encryptTextResult = JSON.stringify(result);
  }

  async decryptData(): Promise<void> {
    // see encryptData()
  }

  async execute_custom_command(event: Event) {
    event.preventDefault();
    if (this.selected === null) return;
    this.custom_cmd_form_reply = "PENDING";
    const command = string_to_command[this.selected];

    const clone = clone_object(this.custom_cmd_form);
    const data_to_send = dict_binval(clone);
    console.log("data to send", data_to_send, this.custom_cmd_form);

    let res: Dictionary|null = null;
    const session = new Session();
    try {
      res = await send_command(session, command, data_to_send, log_fn);
    } catch (e) {
      this.custom_cmd_form_reply = `Error: ${JSON.stringify(e)}`;
      return;
    }

    let hrres = "OK";
    if (!dict_empty(<Dictionary>res)) {
      if (res) {
        hrres = JSON.stringify(dict_hexval(res));
      }
    }
    this.custom_cmd_form_reply = hrres;
  }


  async progress_fun(x: number, max:number=100): Promise<void> {
    if (x > max){
      console.log(`Value bigger than max: ${x} > ${max}`);
      return;
    }
    this.progress = {value: x, max: max};
  }

  async WebcryptTests(): Promise<void> {
    // Run test Webcrypt calls
    this.active_tab = 4;
    this.console = "";
    await this.log_console('\n*** Running test commands\n');

    try{
      await WebcryptTests(this.log_console, this.progress_fun);
    } catch (e) {
      await this.log_console('*** Finished test commands with status FAIL\n\n');
      throw e;
    }

    await this.log_console('*** Finished test commands with status PASS\n\n');

  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}

ul {
  list-style-type: none;
  padding: 0;
}

li {
  display: inline-block;
  margin: 0 10px;
}

a {
  color: #42b983;
}
</style>

