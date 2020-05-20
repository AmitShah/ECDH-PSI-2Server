/*
* @Author: amitshah
* @Date:   2020-05-17 05:11:37
* @Last Modified by:   amitshah
* @Last Modified time: 2020-05-20 05:55:38
*/


var ec = require('elliptic').ec;
var bn = require('bn.js');
const curve = new ec("p256");
const hash = (msg)=>{ return curve.hash().update(msg).digest("hex"); }; 
const red = bn.red(curve.curve.p);
var crypto = require('crypto');


function readBit(buffer, i, bit){
  return (buffer[i] >> bit) % 2;
}

function setBit(buffer, i, bit, value){
  if(value == 0){
    buffer[i] &= ~(1 << bit);
  }else{
    buffer[i] |= (1 << bit);
  }
}

//increment the least signficant bit 
function incrementLSB(buffer){
    for(var i=(buffer.length)-1 ; i>=0; i--){
        for(var b=0; b<8; b++){
            console.debug("iter:",(i+1)*8-(b+1) , " value:", readBit(buffer,i,b));
            if(readBit(buffer,i,b)===0){
                setBit(buffer,i,b);
                console.debug("set bit:",(i+1)*8-(b+1));
                return;
            }
        }        
    }
    throw new Error("no bits left to increment");
}

function tryPoint(r){
    for(;;){
        try{
            return curve.curve.pointFromX(r);
            //return pointFromX(r) no need for custom
        }catch(e){
            //console.error(e);
            //if we cannot encode point we throw a final error to break the for loop
            incrementLSB(r);
            
        }
    }
}


class Alice{
	constructor(){
		this.keyPair = curve.genKeyPair();
	}

	setServerKey(sk){
		this.serverKey = sk;
	}

	compareAndSetServerKey(sks){

		if(!sks.reduce(function(a, b){ 
			if( a.getX().toString(16)===b.getX().toString(16) && a.getY().toString(16) === b.getY().toString(16) ){
				return a;
			}
			return null;
			})){
			throw new Error("server shared keys do not match");
		};
		this.setServerKey(sks[0])
	}
	encodeData(d){

		//G^x
		var c1 = this.keyPair.getPublic();
		//G^r1r2*x*H(alice)
		var c2 = this.serverKey.mul(this.keyPair.getPrivate()).mul(hash(d))
		return [c1.encodeCompressed('hex'),c2.encodeCompressed('hex')];
	}
}

class Bob{
	constructor(){
		this.keyPair = curve.genKeyPair();
	}

	phase2(p1,msg){
		
		var h = hash(msg)
		//G^x*r2*H(bob)+y
		console.log("PHASE_2",p1.mul(h).add(this.keyPair.getPublic()).encodeCompressed('hex'));
		return p1.mul(h).add(this.keyPair.getPublic())
	}

	phase2_b(encodedKeys,msg){
		var self = this;
		return encodedKeys.map(ek=>{
			var p1 = curve.curve.decodePoint(ek,'hex');
			var h = hash(msg)
			console.log("PHASE_2B:",p1.mul(h).add(this.keyPair.getPublic()).encodeCompressed('hex'))
			return p1.mul(h).add(this.keyPair.getPublic());
		}).map(p1=>{
			return p1.encodeCompressed('hex');
		});	
	}

	phase4(p3,pn,serverPk){
		var actual = p3.add(pn.neg());
		var expectedPk = serverPk.mul(this.keyPair.getPrivate());
		console.log( actual.getX().toString(16), expectedPk.getX().toString(16) , 
		actual.getY().toString(16) , expectedPk.getY().toString(16) )
		return actual.getX().toString(16) === expectedPk.getX().toString(16) && 
		actual.getY().toString(16) === expectedPk.getY().toString(16) 
	}

	phase4_b(p3s, pnEncoded, serverPkEncoded){
		var self = this;
		var serverPk = curve.curve.decodePoint(serverPkEncoded,'hex');
		var expectedPkEncoded = serverPk.mul(this.keyPair.getPrivate()).encodeCompressed('hex'); 
		var pn = pnEncoded.map(pn=>{
			return curve.curve.decodePoint(pn,'hex');
		})
		var p3 = p3s.map(ek=>{
			return curve.curve.decodePoint(ek,'hex');	
		});

		for(var i=0; i < p3.length; i++){

			for (var j=0; j< pn.length; j++){
				var actualPkEncoded = p3[i].add(pn[j].neg()).encodeCompressed('hex');
				if(actualPkEncoded === expectedPkEncoded){
					console.log("Found Match. i:",i,"j:",j);
					break;
				}else{
					console.log("No Match. i:",i,"j:",j);
				}
			}

		}
	}
}

class Server{
	constructor(){
		this.keyPair = curve.genKeyPair();
		this.dataSet = {};
	}

	getSharedPublicKey(publicKey){
		return publicKey.mul(this.keyPair.getPrivate());
	}

	getPublic(){
		return this.keyPair.getPublic();
	}

	phase3(p2){
		//G^(x*r2*H(bob)+y)*r1
		return p2.mul(this.keyPair.getPrivate());
	}

	phase3_b(p2s){
		var self = this;
		return p2s.map(ek=>{
			var p2 = curve.curve.decodePoint(ek,'hex');
			return self.phase3(p2);
		}).map(p2=>{
			return p2.encodeCompressed('hex');
		})
	}

	setAliceData(c1,c2){
		//c1 = G^x
		//c2 = //G^r1*r2*x*H(alice)
		this.data = [c1,c2];
	}

	upload(infectedData){
		for(var i=0; i< infectedData.length; i++){
			var id = infectedData[i];
			var key = curve.curve.decodePoint(id[0],'hex').mul(this.keyPair.getPrivate()).encodeCompressed('hex');
			if(!this.dataSet.hasOwnProperty(key)){
				this.dataSet[key] = [];
			}
			this.dataSet[key].push(id[1]);
		}		
	}


}

class Server2 extends Server{


	phase1(){
		//G^x*r2
		return [this.data[0].mul(this.keyPair.getPrivate()),this.data[1]];
	}

	phase1_b(){
		return [Object.keys(this.dataSet),Object.values(this.dataSet).flat()];
	}


	phase4(p3){
		var c2= this.data[1];
		
		return p3.add(c2.neg());
	}

}

S1 = new Server();
S2 = new Server2();

// console.log(S1.getSharedPublicKey(S2.getPublic()).getX().toString(16));
// console.log(S2.getSharedPublicKey(S1.getPublic()).getX().toString(16));




//Offline Mode
Alice = new Alice();
Alice.compareAndSetServerKey([S2.getSharedPublicKey(S1.getPublic()),S1.getSharedPublicKey(S2.getPublic())]);

var InfectedData = [];

const INFECION_DATA_SIZE = 288*14;

for(var i=0; i< INFECION_DATA_SIZE; i++){
	
	if(Math.random() > 0.999){
		console.log("ADDED at position:",i)
		let [c1,c2] = Alice.encodeData("geohash");
		InfectedData.push([c1,c2]);
	}else{
		InfectedData.push(Alice.encodeData(crypto.randomBytes(32)));
	}
	console.log("generating infected data:",i,":",INFECION_DATA_SIZE);
}



S2.upload(InfectedData);
//S1.upload(InfectedData);

//Bob requests data from Server
Bob = new Bob();
// let [p1,p4] = S2.phase1();

// p2 = Bob.phase2(p1, "geohash2");

// p3 = S1.phase3(p2);

// if(!Bob.phase4(p3,p4,S1.keyPair.getPublic())){
//  console.log("invalid");
// }else{
// 	 console.log("valid");
// }


// //G^yr1
// rActual = S2.phase4(p3)

// rExpected = S1.keyPair.getPublic().mul(Bob.keyPair.getPrivate())

// console.log(rActual.getX().toString(16));
// console.log(rExpected.getX().toString(16));
// console.log(rActual.getY().toString(16));
// console.log(rExpected.getY().toString(16));


// p2 = Bob.phase2(p1, "geohash");

// p3 = S1.phase3(p2);

// if(!Bob.phase4(p3,p4,S1.keyPair.getPublic())){
//  console.log("invalid");
// }else{
// 	 console.log("valid");
// }
// //G^yr1
// rActual = S2.phase4(p3)

// rExpected = S1.keyPair.getPublic().mul(Bob.keyPair.getPrivate())

// console.log(rActual.getX().toString(16));
// console.log(rExpected.getX().toString(16));
// console.log(rActual.getY().toString(16));
// console.log(rExpected.getY().toString(16));

var start = Date.now();
console.log("Processing Start:",start);


let [encodedC1, encodedC2] = S2.phase1_b();

encodedPhase2= Bob.phase2_b(encodedC1,"geohash");

encodedPhase3 = S1.phase3_b(encodedPhase2);

Bob.phase4_b(encodedPhase3, encodedC2,S1.keyPair.getPublic().encodeCompressed('hex'))

console.log("Time Delta:",Date.now()-start);

// console.log(c1.encodeCompressed('hex'));
// console.log(c2.encodeCompressed('hex'));
// console.log(p1.encodeCompressed('hex'));
// console.log(p4.encodeCompressed('hex'));




