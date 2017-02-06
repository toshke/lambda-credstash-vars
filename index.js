'use strict'

const AWS = require('aws-sdk');
const crypto = require('crypto');
const AES = require('aes-js');

function loadenvvars(cb) {

    if (process.env.CREDSTASH_VARIABLES_FORCE_LOAD !== '1' &&
        (process.env.CREDSTASH_VARIABLES_LOADED === '1' || process.env.CREDSTASH_VARIABLES_LOAD !== '1')) {
        cb();
        return;
    }

    let dynamodb = new AWS.DynamoDB.DocumentClient({
            apiVersion: '2012-08-10',
            region: process.env.CREDSTASH_REGION
        }),
        kms = new AWS.KMS({
            apiVersion: '2014-11-10',
            region: process.env.CREDSTASH_REGION
        }),
        scanRequestPromise = dynamodb.scan({
            TableName: process.env.CREDSTASH_TABLE,
            Select: 'ALL_ATTRIBUTES'
        }).promise(),
        decodedVars = {},

        writeDecodedVars = () => {
            Object.keys(decodedVars).forEach((k) => {
                process.env[k] = decodedVars[k]
            });
            process.env.CREDSTASH_VARIABLES_LOADED = '1';
            cb();
        },

        failure = (error) => {
            console.error(`Unable to load environment variables: ${error}`);
            if (process.env.CREDSTASH_FAIL_ON_ERROR === '1') {
                process.exit(1);
            } else {
                cb();
            }
        };

    scanRequestPromise.then(function(data) {
        let workObj = {};

        if (data.Items.length == 0) {
            //no variables within the table
            cb();
            return;
        };

        data.Items.forEach((item) => {
            if (workObj[item.name]) {
                if (workObj[item.name].version < item.version) {
                    workObj[item.name] = item;
                }
            } else {
                workObj[item.name] = item;
            }
        });

        //all envvars withing workObj object
        Object.keys(workObj).forEach((k) => {
            const params = {
                CiphertextBlob: new Buffer(workObj[k].key, 'base64'),
            };

            // Hit the KMS API to decrypt the key
            kms.decrypt(params, (error, data) => {
                if (error) {
                    failure(error);
                    return;
                }

                const contents = new Buffer(workObj[k].contents, 'base64');

                // First 32 bytes are the key, the rest is our HMAC key
                const key = data.Plaintext.slice(0, 32);
                const hmacKey = data.Plaintext.slice(32);

                // Add our contents to our HMAC, then check it's correct
                const hmac = crypto.createHmac(workObj[k].digest, hmacKey);
                hmac.update(contents);

                if (workObj[k].hmac !== hmac.digest('hex')) {
                    failure(new Error(`HMACs do not match for env var ${workObj[k].name}`));
                }

                const decrypt = new AES.ModeOfOperation.ctr(key); // eslint-disable-line new-cap
                const plaintext = decrypt.decrypt(contents).toString('utf-8');

                decodedVars[workObj[k].name] = plaintext
                if (Object.keys(decodedVars).length == Object.keys(workObj).length) {
                    writeDecodedVars();
                }
            });
        });
    }, function(error) {
        failure(error);
    });
};

module.exports = loadenvvars;
