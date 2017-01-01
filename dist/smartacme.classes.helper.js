"use strict";
require("typings-global");
let rsaKeygen = require('rsa-keygen');
class SmartacmeHelper {
    createKeypair(bit = 2048) {
        let result = rsaKeygen.generate(bit);
        return {
            publicKey: result.public_key,
            privateKey: result.private_key
        };
    }
}
exports.SmartacmeHelper = SmartacmeHelper;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmNsYXNzZXMuaGVscGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vdHMvc21hcnRhY21lLmNsYXNzZXMuaGVscGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSwwQkFBdUI7QUFDdkIsSUFBSSxTQUFTLEdBQUcsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFBO0FBT3JDO0lBQ0ksYUFBYSxDQUFDLEdBQUcsR0FBRyxJQUFJO1FBQ3BCLElBQUksTUFBTSxHQUFHLFNBQVMsQ0FBQyxRQUFRLENBQUMsR0FBRyxDQUFDLENBQUE7UUFDbkMsTUFBTSxDQUFDO1lBQ0osU0FBUyxFQUFHLE1BQU0sQ0FBQyxVQUFVO1lBQzdCLFVBQVUsRUFBRSxNQUFNLENBQUMsV0FBVztTQUNoQyxDQUFBO0lBQ04sQ0FBQztDQUNKO0FBUkQsMENBUUMifQ==