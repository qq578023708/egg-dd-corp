'use strict';

// 引入钉钉 SDK
const dd = require('./dd');

/**
 * 将钉钉 SDK 挂在到全局 app 对象
 * @param app
 */
module.exports = app => {
  app.addSingleton('dd', init);
};

/**
 * 实例化钉钉 SDK
 * @param config
 * @return {dd}
 */
function init(config) {
  return new dd(config);
}
