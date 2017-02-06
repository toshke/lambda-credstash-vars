'use strict'

const AWS = require('aws-sdk');
const crypto = require('crypto');
const AES = require('aes-js');

function loadenvvars(cb){

  if( process.env.CREDSTASH_VARIABLES_FORCE_LOAD !== '1' &&
          (process.env.CREDSTASH_VARIABLES_LOADED === '1' || process.env.CREDSTASH_VARIABLES_LOAD !== '1')){
      cb();
      return;
  }

  let dynamodb = new AWS.DynamoDB.DocumentClient({apiVersion: '2012-08-10', region: process.env.CREDSTASH_REGION});
  let kms = new AWS.KMS({  apiVersion: '2014-11-10', region : process.env.CREDSTASH_REGION });

  let scanRequestPromise = dynamodb.scan({
    TableName:process.env.CREDSTASH_TABLE,
    Select: 'ALL_ATTRIBUTES'
  }).promise();

  let decodedVars = {}

  let writeDecodedVars = ()=>{
      Object.keys(decodedVars).forEach((k)=>{process.env[k]=decodedVars[k]});
      process.env.CREDSTASH_VARIABLES_LOADED = '1';
      cb();
  };

  scanRequestPromise.then(function(data){
    let workObj = {};

    if(data.Items.length == 0){
        //no variables within the table
        cb();
        return;
    }

    data.Items.forEach((item)=>{
        if(workObj[item.name]){
          if(workObj[item.name].version < item.version){
                workObj[item.name] = item;
          }
        } else {
          workObj[item.name] = item;
        }
    });

    //all envvars withing workObj object
    Object.keys(workObj).forEach((k)=>{
      const params = {
          CiphertextBlob: new Buffer(workObj[k].key, 'base64'),
      };

      // Hit the KMS API to decrypt the key
      kms.decrypt(params, (err, data) => {
          if (err) console.error(err);

          const contents = new Buffer(workObj[k].contents, 'base64');

          // First 32 bytes are the key, the rest is our HMAC key
          const key = data.Plaintext.slice(0, 32);
          const hmacKey = data.Plaintext.slice(32);

          // Add our contents to our HMAC, then check it's correct
          const hmac = crypto.createHmac(workObj[k].digest, hmacKey);
          hmac.update(contents);

          if (workObj[k].hmac !== hmac.digest('hex')) {
              console.error('HMACs do not match');
          }

          const decrypt = new AES.ModeOfOperation.ctr(key);  // eslint-disable-line new-cap
          const plaintext = decrypt.decrypt(contents).toString('utf-8');

          decodedVars[workObj[k].name] = plaintext
          if(Object.keys(decodedVars).length == Object.keys(workObj).length){
              writeDecodedVars();
          }
      });
    });
  }, function(error){
        console.error(`Unable to load environment variables: ${error}`);
        process.exit(1);
  });
}

module.exports = loadenvvars;
