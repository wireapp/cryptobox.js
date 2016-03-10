process.env['NODE_PATH'] = './src';
require('module').Module._initPaths();

assert = require('chai').assert;

cryptobox = require('cryptobox');
sodium = require('libsodium');
Proteus = require('proteus');
