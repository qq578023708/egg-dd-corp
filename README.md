# egg-dd-corp

[![NPM version][npm-image]][npm-url]
[![build status][travis-image]][travis-url]
[![Test coverage][codecov-image]][codecov-url]
[![David deps][david-image]][david-url]
[![Known Vulnerabilities][snyk-image]][snyk-url]
[![npm download][download-image]][download-url]

[npm-image]: https://img.shields.io/npm/v/egg-dd.svg?style=flat-square
[npm-url]: https://npmjs.org/package/egg-dd
[travis-image]: https://img.shields.io/travis/eggjs/egg-dd.svg?style=flat-square
[travis-url]: https://travis-ci.org/eggjs/egg-dd
[codecov-image]: https://img.shields.io/codecov/c/github/eggjs/egg-dd.svg?style=flat-square
[codecov-url]: https://codecov.io/github/eggjs/egg-dd?branch=master
[david-image]: https://img.shields.io/david/eggjs/egg-dd.svg?style=flat-square
[david-url]: https://david-dm.org/eggjs/egg-dd
[snyk-image]: https://snyk.io/test/npm/egg-dd/badge.svg?style=flat-square
[snyk-url]: https://snyk.io/test/npm/egg-dd
[download-image]: https://img.shields.io/npm/dm/egg-dd.svg?style=flat-square
[download-url]: https://npmjs.org/package/egg-dd

适用 egg.js 的钉钉服务端 SDK

## Install

```bash
$ npm i egg-dd-corp --save
```

## Usage

```js
// {app_root}/config/plugin.js
exports.dingtalk = {
  enable: true,
  package: 'egg-dd-corp',
};
```

## Configuration

```js
// {app_root}/config/config.default.js
exports.dd = {
  client: {
    corpId: '',
    appKey: '',
    appSecret: '',
    agentId: Number,
    // 以下配置参数有默认值
    custom: 'boolean 类型，默认为 false，代表应用类型为 “企业内部开发”，true代表 “授权服务商开发”',
    encodingAESKey: 'string 类型，数据加密密钥，用于消息体的加密，长度固定为43个字符，从a-z，A-Z，0-9共62个字符中选取',
    token: 'string 类型，随机字符串，不能为空',
  }
};
```

see [config/config.default.js](config/config.default.js) for more detail.

## API

|参数|说明|补充|
|---|---|---|
|accessToken|钉钉服务端 API 请求数据时需要的access_token，过期时间7000秒|自动获取|
|request|axios 对象，可以发送请求|只能发送钉钉服务端相关请求，自动配置access_token|

<br/>

|方法|说明|参数|返回|补充|
|---|---|---|---|---|
|getSignature| |时间戳，随机字符串，密文|签名|密文可以通过 encrypt 方法获得|
|encrypt| |明文|密文| |
|decrypt| |密文|明文| |
|getAccessToken| | |access_token| |
|bizRegister| |{<br/>call_back_tag：事件类型数组，<br/>url：回调地址，<br/>type："register"(默认) 或 "update"<br/>}|错误信息| |
|bizCallback| |明文，默认 "success"|{<br/>msg_signature：消息体签名，<br/>timeStamp：时间戳，<br/>encrypt：密文，<br/>nonce：随机字符串<br/>}| |

完善中...
## Questions & Suggestions

Please open an issue [here](https://github.com/qq578023708/egg-dd-corp/issues).

## License

[MIT](LICENSE)
