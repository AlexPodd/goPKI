import * as asn1js from 'asn1js';
import { getCrypto, getAlgorithmParameters, CertificationRequest, GeneralName ,AttributeTypeAndValue, Extension, GeneralNames, Attribute, Extensions } from 'pkijs/build'
import { arrayBufferToString, toBase64 } from 'pvutils';


const hashAlg = 'SHA-256'
const signAlg = 'RSASSA-PKCS1-v1_5';


/**
 * @example
 * createPKCS10({ enrollmentID: 'user1', organizationUnit: 'Marketing', organization: 'Farmer Market', state: 'M', country: 'V' })
 *  .then(({csr, privateKey} => {...}))
 */
export async function createPKCS10({ enrollmentID, organizationUnit, organization, state, country, emailID })
{
  console.log("func "+emailID)
  const crypto = getWebCrypto()

  const keyPair = await generateKeyPair(crypto, getAlgorithm(signAlg, hashAlg))

  return {
    csr: `-----BEGIN CERTIFICATE REQUEST-----\n${
      formatPEM(
        toBase64(
          arrayBufferToString(
            await createCSR(keyPair, hashAlg, { enrollmentID, organizationUnit, organization, state, country, emailID })
          )
        )
      )}\n-----END CERTIFICATE REQUEST-----`,
    privateKey: `-----BEGIN PRIVATE KEY-----\n${
      toBase64(arrayBufferToString(await crypto.exportKey('pkcs8', keyPair.privateKey)))
    }\n-----END PRIVATE KEY-----`
  }
}

async function createCSR(keyPair, hashAlg, { enrollmentID, organizationUnit, organization, state, country, emailID }) {
  const pkcs10 = new CertificationRequest();
  pkcs10.version = 0;

  // Subject в правильном порядке
  pkcs10.subject.typesAndValues.push(
    new AttributeTypeAndValue({
      type: '2.5.4.6', // C
      value: new asn1js.Utf8String({ value: country })
    }),
    new AttributeTypeAndValue({
      type: '2.5.4.3', // CN
      value: new asn1js.Utf8String({ value: enrollmentID })
    }),
    new AttributeTypeAndValue({
      type: '2.5.4.8', // ST
      value: new asn1js.Utf8String({ value: state })
    }),
    new AttributeTypeAndValue({
      type: '2.5.4.11', // OU
      value: new asn1js.Utf8String({ value: organizationUnit })
    }),
    new AttributeTypeAndValue({
      type: '2.5.4.10', // O
      value: new asn1js.Utf8String({ value: organization })
    }),
  );
     // Добавим расширение Subject Alternative Name с Email
     const altNames = new GeneralNames({
       names: [new GeneralName({ type: 1, value: emailID })] // rfc822Name
     });

     const sanExtension = new Extension({
       extnID: '2.5.29.17', // subjectAltName
       critical: false,
       extnValue: altNames.toSchema().toBER(false)
     });

     const extensions = new Extensions({ extensions: [sanExtension] });

     // Добавим extensionRequest
     pkcs10.attributes = [
       new Attribute({
         type: '1.2.840.113549.1.9.14', // extensionRequest
         values: [extensions.toSchema()]
       })
     ];

  await pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey);
  await pkcs10.sign(keyPair.privateKey, hashAlg);

  return pkcs10.toSchema().toBER(false);
}

// add line break every 64th character
function formatPEM(pemString)
{
  return pemString.replace(/(.{64})/g, '$1\n')
}

function getWebCrypto() {
  const crypto   = getCrypto()
	if(typeof crypto === 'undefined')
    throw 'No WebCrypto extension found'
  return crypto
}

function getAlgorithm(signAlg, hashAlg) {
  const algorithm = getAlgorithmParameters(signAlg, 'generatekey')
  if('hash' in algorithm.algorithm)
    algorithm.algorithm.hash.name = hashAlg
  return algorithm
}

function generateKeyPair(crypto, algorithm) {
  return crypto.generateKey(algorithm.algorithm, true, algorithm.usages)
}

/**
 * to learn more about asn1, ber & der, attributes & types used in pkcs#10
 * http://luca.ntop.org/Teaching/Appunti/asn1.html
 *
 * guides to SubtleCrypto (which PKIjs is built upon):
 * https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
 */