## Lambda CredsStash environment variables

# Introduction

This library is written for loading environment variables on AWS lambda
from [credstash](https://github.com/fugue/credstash) secrets store.

# Caching

Process environment variables are cached for warm lambda containers, and are
only loaded from DyanmoDB (credstash) for cold containers.

# Usage

Just called imported function and pass callback as code to execute once
variables are loaded.


```
const envvars = require('lambda-credstash-envvars');

exports.table = (event, context, cb) => {
    envvars(()=>{
      console.log(JSON.stringify(process.env),null,2);
      execute_business_logic();
    });
};
```

Behaviour is controlled via Lambda's process environment variables:

- `CREDSTASH_VARIABLES_LOAD` set this to `1` to enable env vars loading process`
- `CREDSTASH_TABLE` - name of DynamoDB table used for storing secrets by credstash
- `CREDSTASH_REGION` - region of DynamoDB table where credstash secrets are store
- `CREDSTASH_VARIABLES_FORCE_LOAD` - if set to `1` variables will not be cached, and will
   be always loaded regardless if running in hot or cold containers.
