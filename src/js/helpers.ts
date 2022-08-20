// Copyright 2022 Nitrokey GmbH
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

import {Dictionary, StatusCallback} from "@/js/types";
import {sha256} from "js-sha256";

class TestError extends Error {

}

export function TEST(tested_condition: boolean, test_description: string, logfn: StatusCallback = async ()=>{} ): void{
    if (tested_condition) {
        if (test_description ){
            const message = "+++ PASS: " + test_description;
            console.log(message);
            logfn(message);
        }
    }
    else {
        const message_fail = "--- TEST FAIL: " + test_description;
        console.log(message_fail);
        logfn(message_fail);
        throw new TestError(message_fail);
    }
}

export function byteToHexString(uint8arr: Uint8Array): string {
    if (!uint8arr) {
        return '';
    }
    let hexStr = '';
    for (let i = 0; i < uint8arr.length; i++) {
        let hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }
    return hexStr.toUpperCase();
}

export function hexStringToByte(str: string): Uint8Array {
    if (!str) {
        return new Uint8Array();
    }
    const a = [];
    for (let i = 0, len = str.length; i < len; i+=2) {
        a.push(parseInt(str.substr(i,2),16));
    }
    return new Uint8Array(a);
}


export function uint8ToUint16(uint_arr: Uint8Array) {
    return (new DataView(uint_arr.buffer)).getUint16(0, false);
}

export function flatten(u8_arr_arr: Array<Uint8Array>): Uint8Array{
    let s= 0;
    for (let i = 0; i < u8_arr_arr.length; i++) {
        s+= u8_arr_arr[i].length;
    }

    let res = new Uint8Array(s);
    let offset = 0;
    for (let i = 0; i < u8_arr_arr.length; i++) {
        res.set(u8_arr_arr[i], offset);
        offset += u8_arr_arr[i].length;
    }
    return res;
}

export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    let c = new Uint8Array(a.length + b.length);
    c.set(a, 0); // FIXME handle empty/null arguments
    c.set(b, a.length);
    return c;
}

export function int2arr(uint: number): Uint8Array {
    let uint_arr = new Uint8Array(1);
    uint_arr[0] = uint;
    return uint_arr;
}

export function values(dictionary: Dictionary) {
    let i, arr = [];
    for(i in dictionary) {
        arr.push(dictionary[i]);
    }
    return arr;
}

export function keys(dictionary:Dictionary): string[] {
    let i, arr = [];
    for(i in dictionary) {
        arr.push(i);
    }
    return arr;
}

export function items(dict: Dictionary){
    let ret = [];
    for(let v in dict){
        ret.push(Object.freeze([v, dict[v]]));
    }
    return Object.freeze(ret);
}

export function getBinaryStr(data: string): Uint8Array {
    let uintArray = new Uint8Array(data.length).fill(67);
    for (let i = 0; i < data.length; ++i) {
        // uintArray[i] = data.charAt(i);
        uintArray[i] = data.charCodeAt(i);
    }
    return uintArray;
}

export function dict_binval(dictionary:Dictionary):Dictionary {
    let res: Dictionary = {};
    for(let i in dictionary) {
        if (typeof dictionary[i] === "object"){
            res[i] = dictionary[i];
        } else if (i === "PIN" || i === "NEWPIN") {
            res[i] = getBinaryStr(<string>dictionary[i]);
        } else {
            res[i] = hexStringToByte(<string>dictionary[i]);
        }
    }
    // console.log("dict_binval",dictionary, res);
    return res;
}

export function clone_object(obj:any) {
    return JSON.parse(JSON.stringify(obj));
}

export function dict_hexval(dictionary:Dictionary):Dictionary {
    let res: Dictionary = {};
    for(let i in dictionary) {
        if (typeof dictionary[i] === "object"){ // Uint8Array
            res[i] = byteToHexString(<Uint8Array>dictionary[i]);
        } else {
            res[i] = dictionary[i];
        }
    }
    return res;
}

export function dict_empty(dict: Dictionary): boolean {
    return Object.keys(dict).length === 0
}

export function delay(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function get_hash(o: string) {
    return sha256(o);
}
