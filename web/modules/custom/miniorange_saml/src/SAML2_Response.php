<?php


namespace Drupal\miniorange_saml;

use DOMDocument;
use DOMElement;
use Drupal\miniorange_saml\XMLSecurityKey;
class SAML2_Response
{
    private $assertions;
    private $destination;
    private $certificates;
    private $signatureData;
    public function __construct(DOMElement $Z0 = NULL)
    {
        $this->assertions = array();
        $this->certificates = array();
        if (!($Z0 === NULL)) {
            goto l7;
        }
        return;
        l7:
        $gF = Utilities::validateElement($Z0);
        if (!($gF !== FALSE)) {
            goto Sg;
        }
        $this->certificates = $gF["\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\163"];
        $this->signatureData = $gF;
        Sg:
        if (!$Z0->hasAttribute("\x44\145\x73\x74\151\x6e\x61\x74\151\157\156")) {
            goto oF;
        }
        $this->destination = $Z0->getAttribute("\104\x65\x73\x74\x69\156\x61\164\151\157\x6e");
        oF:
        $TV = $Z0->firstChild;
        xp:
        if (!($TV !== NULL)) {
            goto Yz;
        }
        if (!($TV->namespaceURI !== "\165\x72\x6e\72\157\x61\x73\x69\x73\72\156\141\155\x65\163\72\x74\143\x3a\x53\101\x4d\114\x3a\62\x2e\60\72\x61\163\163\x65\x72\x74\151\157\156")) {
            goto hQ;
        }
        goto ae;
        hQ:
        if (!($TV->localName === "\101\x73\163\x65\162\164\x69\x6f\x6e" || $TV->localName === "\x45\156\x63\162\171\x70\x74\x65\144\101\x73\163\145\162\x74\x69\x6f\x6e")) {
            goto Uc;
        }
        $this->assertions[] = new SAML2_Assertion($TV);
        Uc:
        ae:
        $TV = $TV->nextSibling;
        goto xp;
        Yz:
    }
    public function getAssertions()
    {
        return $this->assertions;
    }
    public function setAssertions(array $oZ)
    {
        $this->assertions = $oZ;
    }
    public function getDestination()
    {
        return $this->destination;
    }
    public function getCertificates()
    {
        return $this->certificates;
    }
    public function getSignatureData()
    {
        return $this->signatureData;
    }
}
