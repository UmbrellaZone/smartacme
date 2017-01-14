"use strict";
require("typings-global");
const q = require("q");
const plugins = require("./smartacme.plugins");
/**
 * creates a keypair to use with requests and to generate JWK from
 */
exports.createKeypair = (bit = 2048) => {
    let result = plugins.rsaKeygen.generate(bit);
    return {
        publicKey: result.public_key,
        privateKey: result.private_key
    };
};
/**
 * gets an existing registration
 * @executes ASYNC
 */
let getReg = (SmartAcmeArg, location) => {
    let done = q.defer();
    let body = { resource: 'reg' };
    SmartAcmeArg.rawacmeClient.post(location, body, SmartAcmeArg.keyPair, (err, res) => {
        if (err) {
            console.error('smartacme: something went wrong:');
            console.log(err);
            done.reject(err);
            return;
        }
        console.log(JSON.stringify(res.body));
        done.resolve();
    });
    return done.promise;
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic21hcnRhY21lLmhlbHBlcnMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi90cy9zbWFydGFjbWUuaGVscGVycy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUEsMEJBQXVCO0FBQ3ZCLHVCQUFzQjtBQUV0QiwrQ0FBOEM7QUFLOUM7O0dBRUc7QUFDUSxRQUFBLGFBQWEsR0FBRyxDQUFDLEdBQUcsR0FBRyxJQUFJO0lBQ2xDLElBQUksTUFBTSxHQUFHLE9BQU8sQ0FBQyxTQUFTLENBQUMsUUFBUSxDQUFDLEdBQUcsQ0FBQyxDQUFBO0lBQzVDLE1BQU0sQ0FBQztRQUNILFNBQVMsRUFBRSxNQUFNLENBQUMsVUFBVTtRQUM1QixVQUFVLEVBQUUsTUFBTSxDQUFDLFdBQVc7S0FDakMsQ0FBQTtBQUNMLENBQUMsQ0FBQTtBQUVEOzs7R0FHRztBQUNILElBQUksTUFBTSxHQUFHLENBQUMsWUFBdUIsRUFBRSxRQUFnQjtJQUNuRCxJQUFJLElBQUksR0FBRyxDQUFDLENBQUMsS0FBSyxFQUFFLENBQUE7SUFDcEIsSUFBSSxJQUFJLEdBQUcsRUFBRSxRQUFRLEVBQUUsS0FBSyxFQUFFLENBQUE7SUFDOUIsWUFBWSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQzNCLFFBQVEsRUFDUixJQUFJLEVBQ0osWUFBWSxDQUFDLE9BQU8sRUFDcEIsQ0FBQyxHQUFHLEVBQUUsR0FBRztRQUNMLEVBQUUsQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7WUFDTixPQUFPLENBQUMsS0FBSyxDQUFDLGtDQUFrQyxDQUFDLENBQUE7WUFDakQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQTtZQUNoQixJQUFJLENBQUMsTUFBTSxDQUFDLEdBQUcsQ0FBQyxDQUFBO1lBQ2hCLE1BQU0sQ0FBQTtRQUNWLENBQUM7UUFDRCxPQUFPLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUE7UUFDckMsSUFBSSxDQUFDLE9BQU8sRUFBRSxDQUFBO0lBQ2xCLENBQUMsQ0FDSixDQUFBO0lBQ0QsTUFBTSxDQUFDLElBQUksQ0FBQyxPQUFPLENBQUE7QUFDdkIsQ0FBQyxDQUFBIn0=