const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('SolRsaVerifyTest', function () {
  before(async function () {
    this.SolRsaVerifyTest = await ethers.getContractFactory('SolRsaVerifyTest');
  });

  beforeEach(async function () {
    this.solRsaVerifyTest = await (
      await this.SolRsaVerifyTest.deploy()
    ).deployed();
  });

  it('RSA signature', async function () {

    // Link attestation signed payload
    const hexMsg1 = "0x3082013d0414cff805b714b24b3dd30cb4a1bea3745e5c5e73efa1820115308201113081c630819f300d06092a864886f70d010101050003818d0030818902818100b3ad78d0b9c3a0cee4e174aff68670f185484c2b2b12eaf1159cbf35b1a4aca051e8c55596ac20f866ca2936ace92e80b8e4fc1e54231e1599f4970cebd967d1a3c22246ae1e2a92a16f03f5154186a5c3b92fecb1cc96d8a133ad34ac91995db10efe2ee3ecff2491f5cebc298ea0deebe925e7a39d91435ff5b4701d754351020301000104148646df47d7b16bf9c13da881a2d8cdacda8f5490300c020462b52546020462b53356300206000342000a22c6493ea332aae6ae4487f5cff2f6fecc73f9f1bfb011ac4709a149b6ab0f70b7c336c6d2684af7853c589ba7e8ebd2912d53260d898cb4d87778191280451c300c020462b52546020462b53356";

    const modulus = "0xb3ad78d0b9c3a0cee4e174aff68670f185484c2b2b12eaf1159cbf35b1a4aca051e8c55596ac20f866ca2936ace92e80b8e4fc1e54231e1599f4970cebd967d1a3c22246ae1e2a92a16f03f5154186a5c3b92fecb1cc96d8a133ad34ac91995db10efe2ee3ecff2491f5cebc298ea0deebe925e7a39d91435ff5b4701d754351";
    const exponent = "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
    const signature = "0x39fe82b186160e1da096c3641a5925b5a288b749ca84d7ffbf6dbf46faa8feaf3632357869b4d530928506f32af16692319778f797379bd9dc843830c1f3acd134fd2c03e7a0f663ba9e2c2f965a99ac9bffec47e42e592c7f3ea37b82d0eece04e5c1fccb91ec4ba8fc6f5333287d4a7dc551c1fa8bd29b24dcdb65ba22f3f7";

    const result = await this.solRsaVerifyTest.pkcs1Sha256VerifyRawTest(hexMsg1, signature, exponent, modulus);

    console.log('result', result.toString());

    expect(result).to.be.equal(0);

    const tx = await this.solRsaVerifyTest.pkcs1Sha256VerifyRawTestGasEstimate(hexMsg1, signature, exponent, modulus);
    const txResult = await (tx.wait());

    console.log('RSA txResult ==>', txResult.gasUsed.toString());
    console.log('RSA txResult1 ==>', txResult.cumulativeGasUsed.toString());
  });
});
