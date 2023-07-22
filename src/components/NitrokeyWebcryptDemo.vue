<template>
  <div class="hello">
    <h1>{{ msg }}</h1>

    <b-alert show>Note: this demo application does not represent the final state of the product. <br/>
      Notably, there are still some performance improvements planned, which will decrease the WebAuthn popups count. <br/>
      Note: it's been reported that this web application does not work on Microsoft Windows 10.
    </b-alert>

    <b-container fluid="md">
      <div>
        <h2>Step 1: Log in</h2>

        <b-button id="btnReset" @click="login">RESET WEBSMARTCARD AND LOGIN</b-button>
        <b-popover target="btnReset" triggers="hover" placement="top">
          <template #title>Reset WebSmartCard and Login</template>
          Run a factory reset, initialize WebSmartCard with a random seed and login.
          The reset operation is limited only to the WebSmartCard application, and does not remove any other user data.
        </b-popover>

        <h2>Step 2: Generate Key</h2>
        <div>
          <b-form-group
              id="fieldset-3"
              description=""
              label="Key seed"
              label-for="input-3"
              valid-feedback="Thank you!"
          >
            <b-form-input id="input-3" v-model="KEYSEED"
                          placeholder="Enter data after which a key will be generated, e.g. a 7 word passphrase"
                          trim></b-form-input>
            <b-form-input id="input-4" v-model="keyseedHash" placeholder="KEYSEED" trim></b-form-input>
            <br/>
            <b-button id="btnGenerate" @click="generateKeyFromData" :disabled="!logged_in">GENERATE KEY FROM USER
              INPUT
            </b-button>
            <b-popover target="btnGenerate" triggers="hover" placement="top">
              <template #title>Generate new key from seed</template>
              Generate a new derived key, based on the provided seed.
              This key is never stored on the device.
              It can be restored either from the user-supplied seed or from the resulting keyhandle.
            </b-popover>
            or
            <b-button id="btnGenerateRandom" @click="generateKey" :disabled="!logged_in">GENERATE RANDOM KEY</b-button>
            <b-popover target="btnGenerateRandom" triggers="hover" placement="top">
              <template #title>Generate new key</template>
              Generate a new key randomly.
              This key is never stored on the device.
              It can be restored only from the resulting keyhandle.
              The keyhandle can be safely stored in a text file or any secure web service for future restoration and usage.
            </b-popover>
          </b-form-group>

          <h2>Result</h2>
          <b-form-group
              id="fieldset-1"
              description="Current key data"
              label="Keyhandle for the internal use/store"
              label-for="input-1"
              valid-feedback="Correct keyhandle"
              :state="state"
          >
            <b-form-input id="input-1" v-model="KEYHANDLE" :state="state" placeholder="KEYHANDLE" trim
                          disabled></b-form-input>
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
      </div>

      <h2>Step 3: Operation</h2>
      <div>
        <b-tabs content-class="mt-3" v-model="active_tab">
          <b-tab title="Sign" active>
            <p>Here you can sign data</p>

            <b-form-input v-model="text" placeholder="Enter data to hash and sign"></b-form-input>
            <b-form-input v-model="hash" placeholder="Calculated hash" disabled></b-form-input>
            <b-form-input v-model="signature" placeholder="Signature" disabled></b-form-input>
            <b-form-input v-model="SignatureCorrect" placeholder="Signature verified?" disabled></b-form-input>
            <button @click="signData" :disabled="!logged_in || !KEYHANDLE">SIGN DATA</button>

          </b-tab>
          <b-tab title="Encrypt">
            <p>Data encryption (run in browser using public key from keyhandle)</p>

            <b-form-input v-model="encryptText" placeholder="Enter data to encrypt"></b-form-input>
            <b-form-textarea
                placeholder="Here will be encryption result"
                v-model="encryptTextResult"
                rows="3"
                max-rows="12"
                disabled
            ></b-form-textarea>

            <button @click="encryptData" :disabled="!KEYHANDLE">ENCRYPT DATA</button>

          </b-tab>
          <b-tab title="Decrypt">
            <p>Data decryption</p>
            <b-form-textarea
                placeholder="Here will be encryption result"
                v-model="encryptTextResult"
                rows="3"
                max-rows="12"
            ></b-form-textarea>

            <b-form-input v-model="decryptText" placeholder="Here decrypted data will be presented" disabled></b-form-input>
            <button @click="decryptData" :disabled="!logged_in || !KEYHANDLE">DECRYPT DATA</button>
          </b-tab>

          <b-tab title="Custom">
            <p>Custom commands</p>

            <b-form id="custom_cmd_form" @submit="execute_custom_command" @submit.stop.prevent>
              <b-form-select v-model="selected" :options="commands"/>


              <div v-for="p of params">
                <b-input-group :prepend="p.placeholder" class="mt-3">
                  <b-form-input v-model="custom_cmd_form[p.name]"></b-form-input>
                </b-input-group>
              </div>

              <b-input-group prepend="Session Token" class="mt-3">
                <b-form-input v-model="logged_in" trim disabled></b-form-input>
              </b-input-group>

              <b-button type="submit" variant="primary" class="mt-3">Execute</b-button>
            </b-form>

            <b-input-group prepend="Execution Status" class="mt-3">
              <b-form-input v-model="custom_cmd_form_reply_status" disabled></b-form-input>
            </b-input-group>


<!--            TODO: handle boolean value for the status unlocked result -->
            <div v-for="(value, key) of custom_cmd_form_reply_obj">

              <b-input-group :prepend="key" class="mt-3">
                <b-form-input v-model="custom_cmd_form_reply_obj[key]" disabled></b-form-input>
              </b-input-group>

            </div>

          </b-tab>

          <b-modal ref="my-modal" hide-footer centered>
            <div class="d-block text-center">
              <h3>Executing command, please wait</h3>
            </div>
          </b-modal>

          <b-tab title="Console">
            <p>Console data</p>

            <button @click="clear_console">Clear</button>


<!--            Progress bar for the test execution (currently disabled)-->
            <b-progress-bar v-model="progress.value" :max="progress.max" variant="success" show-progress
                            show-value></b-progress-bar>
            <b-form-textarea
                id="console"
                placeholder="Enter something..."
                v-model="console"
                rows="3"
                max-rows="12"
            ></b-form-textarea>


          </b-tab>

          <b-tab title="Help">
            <ol>
              <li>
                SET_PIN command can only be executed once during the working lifecycle. Subsequent PIN changes must be done using the CHANGE_PIN command.
              </li>
              <li>
                After setting the PIN, users need to log in to access the commands with the LOGIN command, which assigns a session token.
              </li>
              <li>
                To invalidate the session token, users can use the LOGOUT command.
              </li>
            </ol>
          </b-tab>

        </b-tabs>

        <h2>Step 4: Finish working with the device</h2>
        <b-button id="btnLogout" @click="logout" :disabled="!logged_in">LOGOUT</b-button>
        <b-popover target="btnLogout" triggers="hover" placement="top">
          <template #title>Logout</template>
          Ask device to invalidate the session token, and remove all unencrypted WebSmartCard secrets from
          the device's RAM memory.
        </b-popover>


      </div>
    </b-container>


  </div>
</template>

<script lang="ts">
import {Component, Prop, Vue} from 'vue-property-decorator';
import {
  CommandLoginParams,
  CommandSetPinParams, Webcrypt_Decrypt, WEBCRYPT_ENCRYPT,
  Webcrypt_FactoryReset,
  WEBCRYPT_GENERATE,
  WEBCRYPT_GENERATE_FROM_DATA,
  Webcrypt_Login,
  Webcrypt_Logout, WEBCRYPT_OPENPGP_DECRYPT, WEBCRYPT_OPENPGP_INFO,
  Webcrypt_SetPin,
  WEBCRYPT_SIGN, WEBCRYPT_VERIFY,
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
  keys, number_to_short, uint8ToUint16
} from "@/js/helpers";
import {sha256} from "js-sha256";
import {send_command} from "@/js/transport";
import {commands_parameters, string_to_command} from "@/js/constants";
import {Session} from "@/js/session";
import {Dictionary} from "@/js/types";
import {log_fn} from "@/js/logs";
import {WebcryptTests} from "@/js/tests";

// import {openpgpTests_ext} from "@/js/openpgp_tests";


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
  custom_cmd_form_reply_status = "";
  custom_cmd_form_reply_obj = {};
  active_tab = 0;
  progress = {value: 0, max: 100};
  logged_in = "";
  encryptText = "";
  encryptTextResult = "";
  decryptText = "";
  SignatureCorrect = "not verified";

  get params() {
    this.custom_cmd_form_reply = "";
    this.custom_cmd_form_reply_status = "";
    this.custom_cmd_form_reply_obj = {};

    if (this.selected.length === 0) {
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
    return await WEBCRYPT_VERIFY(this.log_console, this.PUBKEY, this.signature, this.hash);
  }

  async SignatureVerified() {
    if (this.signature == "") {
      return "not verified";
    }

    if (await this.verify()) {
      return "verified!";
    }

    return "not correct";
  }

  get state() {
    // when it passed validation
    return this.KEYHANDLE != "";
    // return false;
  }

  hideModal() {
    this.$refs['my-modal'].hide()
  }

  async log_console(s: string): Promise<void> {
    console.log(s);
    this.console += `${s}\n`

    // Quick UI hack to show modal window for the time of command processing
    if (s.indexOf("Attempting to run command") !== -1) {
      // Starting
      this.$refs['my-modal'].show()
    } else if (s.indexOf("executed successfully") !== -1
        || s.indexOf("Error: ") !== -1) {
      // Finished
      this.$refs['my-modal'].hide()
    }

    return Promise.resolve();
  }

  async generateKey(): Promise<void> {
    const genkey = await WEBCRYPT_GENERATE(this.log_console);
    this.KEYHANDLE = genkey.keyhandle;
    this.PUBKEY = genkey.pubkey;
  }

  async login(): Promise<void> {
    await Webcrypt_FactoryReset(this.log_console);
    const DEFAULT_PIN = '123456';
    await Webcrypt_SetPin(this.log_console, new CommandSetPinParams(DEFAULT_PIN));
    const res = await Webcrypt_Login(this.log_console, new CommandLoginParams(DEFAULT_PIN));
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
    this.SignatureCorrect = await this.SignatureVerified();
  }

  async encryptData(): Promise<string> {
    const result = await WEBCRYPT_ENCRYPT(this.log_console, this.encryptText, this.PUBKEY, this.KEYHANDLE);
    this.encryptTextResult = JSON.stringify(result);
    return this.encryptTextResult;
  }

  async decryptData(): Promise<void> {

    try{
      const commandDecryptParams = JSON.parse(this.encryptTextResult);
      const decrypt_result = await Webcrypt_Decrypt(this.log_console, commandDecryptParams);

      const decoder = new TextDecoder();
      const text_len = uint8ToUint16(hexStringToByte(decrypt_result.DATA).slice(0,2), true);
      const decoded_text_no_pad_cut = decoder.decode( hexStringToByte(decrypt_result.DATA).slice(2, text_len+2) );
      this.decryptText = decoded_text_no_pad_cut;
    }
    catch (e) {
      this.decryptText = `Error encountered: ${e}`;
    }

  }

  async execute_custom_command(event: Event) {
    event.preventDefault();
    if (this.selected.length === 0) return;
    this.custom_cmd_form_reply = "PENDING";
    const command = string_to_command[this.selected];

    const clone = clone_object(this.custom_cmd_form);
    const data_to_send = dict_binval(clone);
    console.log("data to send", data_to_send, this.custom_cmd_form);

    let res: Dictionary|null = null;
    const session = new Session();
    session.token = this.logged_in;
    try {
      res = await send_command(session, command, data_to_send, this.log_console); // log_fn
      if (this.selected === "LOGIN") {
        this.logged_in = res.TP;
      }

    } catch (e) {
      this.custom_cmd_form_reply = `Error: ${JSON.stringify(e)}`;
      this.custom_cmd_form_reply_status = `Error: ${JSON.stringify(e)}`;
      return;
    }


    let hrres = "OK";
    let hrres_o = {};
    if (!dict_empty(<Dictionary>res)) {
      if (res) {
        hrres = JSON.stringify(dict_hexval(res));
        hrres_o = dict_hexval(res);
        this.custom_cmd_form_reply_status = "OK";
      }
    }
    this.custom_cmd_form_reply = hrres;
    this.custom_cmd_form_reply_obj = hrres_o;
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

  // async openpgpTests(): Promise<void> {
  //   await openpgpTests_ext(this.log_console);
  // }


}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
h3 {
  margin: 40px 0 0;
}

h2 {
  margin: 40px 20px 20px;
}

ul {
  list-style-type: none;
  padding: 0;
}

li {
  margin: 0 10px;
  text-align: justify;
}

a {
  color: #42b983;
}
</style>

