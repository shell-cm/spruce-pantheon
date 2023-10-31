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
    public function __construct(DOMElement $mk = NULL)
    {
        $this->assertions = array();
        $this->certificates = array();
        if (!($mk === NULL)) {
            goto pN;
        }
        return;
        pN:
        $kk = Utilities::validateElement($mk);
        if (!($kk !== FALSE)) {
            goto mn;
        }
        $this->certificates = $kk["\x43\145\162\x74\x69\146\151\143\x61\x74\x65\x73"];
        $this->signatureData = $kk;
        mn:
        if (!$mk->hasAttribute("\x44\x65\x73\164\x69\x6e\141\x74\151\157\x6e")) {
            goto eF;
        }
        $this->destination = $mk->getAttribute("\x44\x65\163\x74\x69\156\x61\164\151\157\156");
        eF:
        $Ci = $mk->firstChild;
        OF:
        if (!($Ci !== NULL)) {
            goto V6;
        }
        if (!($Ci->namespaceURI !== "\x75\162\156\x3a\157\x61\x73\x69\163\72\x6e\x61\x6d\x65\163\72\164\x63\x3a\x53\x41\x4d\x4c\72\x32\56\60\x3a\x61\x73\163\145\162\164\x69\x6f\156")) {
            goto el;
        }
        goto t_;
        el:
        if (!($Ci->localName === "\x41\x73\x73\x65\x72\164\151\157\156" || $Ci->localName === "\105\156\x63\x72\171\x70\164\145\144\101\x73\163\145\162\x74\151\157\156")) {
            goto zN;
        }
        $this->assertions[] = new SAML2_Assertion($Ci);
        zN:
        t_:
        $Ci = $Ci->nextSibling;
        goto OF;
        V6:
    }
    public function getAssertions()
    {
        return $this->assertions;
    }
    public function setAssertions(array $NQ)
    {
        $this->assertions = $NQ;
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
