/*
* @Author: amitshah
* @Date:   2020-05-17 05:11:37
* @Last Modified by:   amitshah
* @Last Modified time: 2020-05-17 19:15:39
*/


var ec = require('elliptic').ec;
var bn = require('bn.js');
const curve = new ec("p256");
const hash = (msg)=>{ return curve.hash().update(msg).digest("hex"); }; 
const red = bn.red(curve.curve.p);



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
		//G^x*r2*H(bob)+y
		return p1.mul(h).add(this.keyPair.getPublic())
	}

	phase4(p3,pn,serverPk){
		var actual = p3.add(pn.neg());
		var expectedPk = serverPk.mul(this.keyPair.getPrivate());
		return actual.getX().toString(16) === expectedPk.getX().toString(16) && 
		actual.getY().toString(16) === expectedPk.getY().toString(16) 
	}
}

class Server{
	constructor(){
		this.keyPair = curve.genKeyPair();
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
	setAliceData(c1,c2){
		//c1 = G^x
		//c2 = //G^r1*r2*x*H(alice)
		this.data = [c1,c2];
	}
}

class Server2 extends Server{

	

	phase1(){
		//G^x*r2
		return [this.data[0].mul(this.keyPair.getPrivate()),this.data[1]];
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
let [c1,c2] = Alice.encodeData("geohash");

S2.setAliceData(c1,c2);
S1.setAliceData(c1,c2);

//Bob requests data from Server
Bob = new Bob();
let [p1,p4] = S2.phase1();

p2 = Bob.phase2(p1, "geohash2");

p3 = S1.phase3(p2);

if(!Bob.phase4(p3,p4,S1.keyPair.getPublic())){
 console.log("invalid");
}else{
	 console.log("valid");
}


//G^yr1
rActual = S2.phase4(p3)

rExpected = S1.keyPair.getPublic().mul(Bob.keyPair.getPrivate())

console.log(rActual.getX().toString(16));
console.log(rExpected.getX().toString(16));
console.log(rActual.getY().toString(16));
console.log(rExpected.getY().toString(16));


p2 = Bob.phase2(p1, "geohash");

p3 = S1.phase3(p2);

if(!Bob.phase4(p3,p4,S1.keyPair.getPublic())){
 console.log("invalid");
}else{
	 console.log("valid");
}
//G^yr1
rActual = S2.phase4(p3)

rExpected = S1.keyPair.getPublic().mul(Bob.keyPair.getPrivate())

console.log(rActual.getX().toString(16));
console.log(rExpected.getX().toString(16));
console.log(rActual.getY().toString(16));
console.log(rExpected.getY().toString(16));









