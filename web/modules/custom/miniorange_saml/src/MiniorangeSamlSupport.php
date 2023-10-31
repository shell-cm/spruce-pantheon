<?php


namespace Drupal\miniorange_saml;

use Drupal\miniorange_saml\MiniorangeSAMLConstants;
use GuzzleHttp\Exception\RequestException;
class MiniorangeSamlSupport
{
    public $email;
    public $phone;
    public $query;
    public $query_type;
    public function __construct($vd, $YV, $BJ, $UC)
    {
        $this->email = $vd;
        $this->phone = $YV;
        $this->query = $BJ;
        $this->query_type = $UC;
    }
    public function sendSupportQuery()
    {
        $o_ = \Drupal::service("\x65\170\164\145\156\x73\151\157\x6e\x2e\x6c\x69\163\x74\x2e\155\157\x64\x75\154\x65")->getExtensionInfo("\155\151\x6e\151\x6f\x72\141\x6e\147\145\137\x73\141\x6d\x6c");
        $Bo = $o_["\x76\145\x72\x73\x69\157\x6e"];
        $Lf = phpversion();
        $YE = $this->query_type === "\x4e\145\167\40\x46\145\x61\164\165\162\145\x20\122\145\x71\165\145\163\x74" ? "\50\116\145\167\40\106\145\x61\x74\165\x72\x65\40\x52\x65\161\165\145\x73\x74\51" : '';
        $this->query = "\x5b\x44\162\165\160\141\x6c\x20" . Utilities::mo_get_drupal_core_version() . "\40\123\101\115\x4c\x20\x53\120\x20" . ucfirst(strtolower(MiniorangeSAMLConstants::PLUGIN_VERSION)) . "\x20" . $YE . "\x20\x7c\x20" . $Bo . "\40\x7c\40\x50\110\120\40" . $Lf . "\x20\x5d\40" . $this->query;
        $Cm = array("\x63\157\x6d\160\141\156\171" => $_SERVER["\123\x45\122\x56\105\x52\x5f\x4e\x41\115\105"], "\x65\155\141\x69\154" => $this->email, "\x63\143\x45\x6d\141\151\x6c" => "\x64\x72\165\160\141\x6c\163\165\x70\160\157\x72\x74\100\x78\145\x63\x75\x72\151\x66\171\x2e\143\x6f\x6d", "\x70\150\157\x6e\145" => $this->query_type != "\x44\145\x6d\x6f\40\x52\145\161\x75\x65\163\164" ? $this->phone : '', "\x71\x75\x65\x72\171" => $this->query);
        $Wa = json_encode($Cm);
        $sc = MiniorangeSAMLConstants::BASE_URL . "\x2f\x6d\x6f\141\x73\x2f\162\145\163\164\57\x63\x75\163\164\157\155\x65\x72\x2f\x63\x6f\156\164\x61\143\164\x2d\x75\x73";
        try {
            $Yq = \Drupal::httpClient()->request("\x50\117\x53\124", $sc, ["\x62\157\144\x79" => $Wa, "\x61\154\154\x6f\x77\137\x72\145\x64\x69\x72\145\x63\164\x73" => TRUE, "\x68\x74\164\160\137\x65\x72\x72\x6f\x72\163" => FALSE, "\x64\x65\143\157\x64\x65\137\143\x6f\x6e\164\x65\x6e\x74" => true, "\x76\x65\162\x69\x66\x79" => FALSE, "\x68\x65\141\x64\x65\x72\163" => array("\x43\x6f\x6e\164\x65\156\x74\55\124\x79\x70\x65" => "\x61\x70\160\154\151\x63\x61\x74\x69\157\x6e\57\152\163\157\156", "\101\165\164\150\157\162\x69\x7a\141\x74\x69\x6f\x6e" => "\102\141\163\x69\143")]);
        } catch (RequestException $J9) {
            \Drupal::logger("\x6d\151\x6e\151\157\162\x61\156\x67\x65\x5f\x73\x61\x6d\x6c")->notice("\105\162\x72\157\162\x20\x61\164\x20\x25\155\x65\164\x68\157\x64\40\157\146\40\45\x66\x69\154\x65\72\40\x25\x65\x72\162\x6f\162", array("\x25\x6d\145\x74\150\157\144" => "\163\145\x6e\x64\123\x75\x70\x70\x6f\162\164\x51\165\x65\x72\x79", "\45\x66\x69\x6c\x65" => "\115\x69\156\x69\157\x72\x61\156\147\x65\123\101\115\114\123\165\x70\x70\x6f\162\x74\56\x70\x68\160", "\x25\x65\x72\x72\x6f\162" => $J9->getMessage()));
            return false;
        }
        return true;
    }
}
