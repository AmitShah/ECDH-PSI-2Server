/*
* @Author: amitshah
* @Date:   2020-05-27 02:23:06
* @Last Modified by:   amitshah
* @Last Modified time: 2020-05-27 03:02:36
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
		return [c1,c2];
	}


}

class Bob{
	constructor(){
		this.keyPair = curve.genKeyPair();
	}

	phase2(p1,msg){
		var h = hash(msg)
		//G^x*H(bob)*y
		//console.log("G^x*h_bob*y",p1.mul(h).mul(this.keyPair.getPrivate()));
		return p1.mul(h).mul(this.keyPair.getPrivate());
	}
	

	phase4(p3,pn){
		return p3.add(pn.mul(this.keyPair.getPrivate()).neg());
		// //var expectedPk = serverPk.mul(this.keyPair.getPrivate());
		// console.log( actual.getX().toString(16), expectedPk.getX().toString(16) , 
		// actual.getY().toString(16) , expectedPk.getY().toString(16) )
		// return actual.getX().toString(16) === expectedPk.getX().toString(16) && 
		// actual.getY().toString(16) === expectedPk.getY().toString(16) 
	}

}

class Server{
	constructor(){
		this.keyPair = curve.genKeyPair();
		this.dataSet = {};
		this.ephemerealKey = curve.genKeyPair();
	}

	getSharedPublicKey(publicKey){
		this.otherServerPk = publicKey;
		return publicKey.mul(this.keyPair.getPrivate());
	}

	getPublic(){
		return this.keyPair.getPublic();
	}

	phase3(p2){
		//p2 = G^x*h_bob*y
		//return
		//G^(x*r2*H(bob)+y)*r1+c1, Hash(G^r1c1)
		return [p2.mul(this.keyPair.getPrivate()).add(this.ephemerealKey.getPublic()), 
		hash(this.otherServerPk.mul(this.ephemerealKey.getPrivate()).encodeCompressed('hex'))];
	}

	phase4(p2){
		//p2 = G^x*h_bob*y
		//return
		//G^((x*r2*H(bob)+y)*r1+c1)*r2+r1*C1, Hash(G^r1c1)
		return [p2.mul(this.keyPair.getPrivate()).add(this.otherServerPk.mul(this.ephemerealKey.getPrivate())), 
		hash(this.otherServerPk.mul(this.ephemerealKey.getPrivate()).encodeCompressed('hex'))];
	}


	setAliceData(c1,c2){
		//c1 = G^x
		//c2 = //G^r1*r2*x*H(alice)
		this.data = [c1,c2];
	}

	result(p5){

		//p5 = G^C2R1+C1R2
		return p5.add(this.otherServerPk.mul(this.ephemerealKey.getPrivate()).neg())
	}

	


}

class Server2 extends Server{


	phase1(){
		//G^x, G^x*r1*r2*h_alice
		return [this.data[0],this.data[1]];
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

let [c1,c2] = Alice.encodeData("geohash");


S1.setAliceData(c1,c2);
S2.setAliceData(c1,c2);


Bob = new Bob();

let [p1,p5] = S2.phase1();

let p2 = Bob.phase2(p1, "geohash2");

let [p3,h1] = S1.phase3(p2);

let [p4,h2] = S2.phase4(p3) 

let p6 = Bob.phase4(p4,p5);

console.log("c2 from S2:", p5.encodeCompressed('hex'));
console.log("p4 from S2:", p6.isInfinity());

let r1 = S1.result(p6);
let r2 = S2.result(p6);

console.log(h1);
console.log(h2);
console.log(hash(r1.encodeCompressed('hex')));
console.log(hash(r2.encodeCompressed('hex')));


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



// console.log(c1.encodeCompressed('hex'));
// console.log(c2.encodeCompressed('hex'));
// console.log(p1.encodeCompressed('hex'));
// console.log(p4.encodeCompressed('hex'));




