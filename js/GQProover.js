import BN from "bn.js";
import SHA256 from "crypto-js/sha256";
import MD5 from "crypto-js/md5";
import CryptoJS from "crypto-js";
import { pki, util, md, rsa, mgf } from "node-forge";
import forge from "node-forge";

class GQProover {
  async testRSAPSS() {
    const keyPair = await new Promise((res, rej) =>
      rsa.generateKeyPair({ bits: 4096, workers: 2 }, (err, keypair) =>
        err ? rej(err) : res(keypair)
      )
    );
    const md = forge.md.sha1.create();
    md.update("sign this", "utf8");
    const pss = forge.pss.create({
      md: forge.md.sha1.create(),
      mgf: forge.mgf.mgf1.create(forge.md.sha1.create()),
      saltLength: 20
      // optionally pass 'prng' with a custom PRNG implementation
      // optionalls pass 'salt' with a forge.util.ByteBuffer w/custom salt
    });

    const mHash = md.digest().getBytes();
    const passportHash = Buffer.from(md.digest().getBytes(), "latin1").toString(
      "hex"
    );
    // md.start();
    // md.update(passportHash, "hex");
    // const h_ = Buffer.from(md.digest().getBytes(), "latin1").toString("hex");
    const pkeyHex = new BN(keyPair.publicKey.n.toString(), 10).toString("hex");
    const signature = keyPair.privateKey.sign(md, pss);
    const signatureHex = Buffer.from(signature, "latin1").toString("hex");
    const d = pki.rsa.decrypt(signature, keyPair.publicKey, true, false);
    const digest = Buffer.from(d, "latin1").toString("hex");
    const h_ = digest.slice(-42).slice(0, 40);
    const mgfmd = forge.md.sha1.create();
    const mgf1 = mgf.mgf1.create(mgfmd);
    const mask = mgf1.generate(
      Buffer.from(h_, "hex").toString("latin1"),
      512 - 20 - 1
    );
    try {
      const verified = keyPair.publicKey.verify(mHash, signature, pss);
      console.log({ verified });
    } catch (e) {
      console.log(e);
    }
    console.log({
      h_,
      passportHash,
      pkeyHex,
      signatureHex,
      digest,
      mask: Buffer.from(mask, "latin1").toString("hex")
    });
  }

  async testRSAPKCS() {
    const passportData = "xxx";
    var crypt = new Crypt({ md: "sha256" });
    const passportHash = CryptoJS.enc.Hex.stringify(SHA256(passportData));
    const keyPair = await new Promise((res, rej) =>
      rsa.generateKeyPair({ bits: 4096, workers: 2 }, (err, keypair) =>
        err ? rej(err) : res(keypair)
      )
    );
    console.log({ keyPair });
    const md = forge.md.sha256.create(),
    const signature = keyPair.privateKey.sign(md);

    const signature = crypt.signature(keyPair.privateKey, passportData);
    const pkeyHex = new BN(keyPair.publicKey.n.toString(), 10).toString("hex");
    const signatureHex = Buffer.from(signature, "latin1").toString("hex");
    const d = pki.rsa.decrypt(signature, keyPair.publicKey, true, false);
    const passportHashDigest = Buffer.from(d, "latin1").toString("hex");
    console.log({
      pkeyHex,
      keyPair,
      signature,
      passportHashDigest,
      passportHash
    });
    const proof = this.createProof({
      n: pkeyHex,
      e: 65537,
      signature: Buffer.from(parsed.signature, "base64").toString("hex"),
      publicKey:
        "869c20a7d0adb3234b2cf62c536ba40fd2ef76dd486aeb0df6bd36c336487a40",
      passportHash,
      passportHashDigest
    });
    console.log({ proof });
    console.log(proof.ts.join('","'), proof.ds.join('","'));
  }

  randomBignum(byteLength) {
    const rand = CryptoJS.lib.WordArray.random(byteLength / 2);
    const randHex = CryptoJS.enc.Hex.stringify(rand);
    const randBuf = Buffer.from(randHex, "hex");
    return new BN(randBuf, "hex");
  }

  createProof({
    n,
    e,
    signature,
    passportHash,
    passportHashDigest,
    publicKey
  }) {
    const bn_n = new BN(n, "hex");
    const bn_e = new BN(e, 10);
    const bn_sig = new BN(signature, "hex");
    const bn_pk = new BN(publicKey, "hex");
    const bn_passportHash = new BN(passportHash, "hex");

    const nonceSeconds = (Date.now() / 1000).toFixed(0);
    const bn_nonce = new BN(nonceSeconds, 10);

    // Step 1.
    const Ts = [];
    const rs = [];
    let toHash = "";
    for (let i = 0; i < 8; i++) {
      const r = this.randomBignum(n.length);
      rs.push(r);
      console.log(`r${i}:`, r.toString("hex"));
      const T = r
        .toRed(BN.red(bn_n))
        .redPow(bn_e)
        .fromRed(); //calculates modexp.
      console.log(`T${i}:`, T.toString("hex"));
      toHash = toHash.concat(T.toString("hex", 128));
    }
    let unique = bn_passportHash
      .toString("hex", 64)
      .concat(bn_pk.toString("hex", 64), bn_nonce.toString("hex", 64));
    toHash = toHash.concat(unique);
    const toHashWordArray = CryptoJS.enc.Hex.parse(toHash);
    let randomOracleHash = CryptoJS.enc.Hex.stringify(SHA256(toHashWordArray));
    console.log({ toHash, randomOracleHash });

    let ts = [];
    let ds = [];
    for (let i = 0; i < 8; i++) {
      const bn_d = new BN(randomOracleHash.slice(i * 4, i * 4 + 4), "hex");
      ds[i] = bn_d.toString("hex", 4);
      if (bn_d.cmp(new BN(2)) < 1)
        throw new Error("D < 3, need to retry random hash");
      const t = bn_sig
        .toRed(BN.red(bn_n))
        .redPow(bn_d)
        .fromRed(); //calculates modexp.
      console.log({ t: t.toString("hex") });
      t = t.mul(rs[i]).mod(bn_n);
      console.log({ t: t.toString("hex") });
      ts.push(t.toString("hex", 128));
    }
    const bn_inverseDigest = new BN(passportHashDigest, "hex");
    let inverseDigest = bn_inverseDigest.invm(bn_n).toString("hex", 128); //solidity is expensive to calculate invm so we calculate this off-chain
    ts = ts.map(_ => "0x" + _);
    ds = ds.map(_ => "0x" + _);
    n = "0x" + n;
    passportHash = "0x" + passportHash;
    passportHashDigest = "0x" + passportHashDigest;
    inverseDigest = "0x" + inverseDigest;
    publicKey = "0x" + publicKey;
    unique = "0x" + unique;
    randomOracleHash = "0x" + randomOracleHash;
    return {
      randomOracleHash,
      ts,
      ds,
      e,
      n,
      passportHashDigest,
      inverseDigest,
      passportHash,
      publicKey,
      nonce: "0x" + bn_nonce.toString("hex", 64),
      unique
    };
  }
}

const proover = new GQProover();
proover.testRSAPSS();
// proover.testRSAPKCS()
