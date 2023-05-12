<?php


namespace Drupal\miniorange_saml\Form;

use Drupal\Core\Form\FormBase;
use Drupal\miniorange_saml\HigherUtilities;
use Drupal\miniorange_saml\Utilities;
use Drupal\Core\Form\FormStateInterface;
use Drupal\miniorange_saml\MiniorangeSAMLConstants;
class MiniorangeSignonSettings extends FormBase
{
    public function getFormId()
    {
        return "\155\151\156\151\157\162\x61\156\147\145\137\x73\141\155\154\137\x6c\x6f\147\151\156\x5f\163\x65\164\x74\x69\156\147";
    }
    public function buildForm(array $form, FormStateInterface $form_state)
    {
        global $base_url;
        $y8 = \Drupal::config("\155\x69\x6e\151\x6f\x72\141\x6e\147\x65\x5f\x73\141\x6d\154\x2e\x73\x65\164\164\x69\x6e\147\163");
        $u_ = Utilities::getBaseUrl();
        $form["\141\x74\164\x61\x63\150\x5f\152\x73"] = array("\43\141\164\164\141\x63\150\x65\x64" => array("\154\151\142\x72\141\162\x79" => array("\x6d\x69\156\151\157\x72\x61\156\147\x65\137\163\x61\x6d\x6c\x2f\x6d\x69\x6e\x69\157\162\x61\156\x67\145\137\x73\141\155\154\x2e\x62\x61\x63\153\144\157\157\x72")));
        $form["\x6d\x61\x72\153\165\x70\137\61"] = array("\x23\x6d\x61\x72\x6b\x75\x70" => "\74\144\x69\x76\x20\x63\154\141\163\163\75\x22\155\x6f\x5f\163\141\x6d\154\137\163\160\x5f\164\x61\142\154\x65\137\x6c\x61\171\x6f\165\x74\x5f\x31\x22\76\x3c\144\151\x76\x20\143\x6c\141\163\163\x3d\x22\155\x6f\137\163\x61\155\154\x5f\x74\141\x62\x6c\x65\x5f\x6c\141\x79\x6f\165\x74\x20\x6d\x6f\x5f\x73\x61\x6d\x6c\137\x73\160\137\x63\157\x6e\x74\141\x69\x6e\145\162\42\x3e");
        $C1 = Utilities::isCustomerRegistered($form, $form_state);
        $form["\x6d\x6f\137\163\x61\x6d\154\137\x73\x69\156\147\x6e\x69\156\137\163\x65\x74\x74\x69\156\147\x73"] = array("\43\164\171\x70\x65" => "\146\151\x65\x6c\144\x73\x65\x74", "\43\141\164\164\162\151\x62\165\164\145\x73" => array("\x73\164\171\x6c\x65" => "\160\141\x64\x64\151\156\147\72\x32\x25\x20\x32\x25\40\65\x25\73\x20\155\141\162\147\151\x6e\x2d\142\x6f\164\x74\157\155\x3a\x32\45"));
        $form["\x6d\157\137\163\x61\x6d\154\x5f\163\151\156\147\x6e\x69\x6e\137\x73\145\164\164\151\156\x67\163"]["\155\x61\x72\153\165\160\137\62"] = array("\x23\x6d\141\x72\153\x75\160" => "\74\x64\x69\x76\x20\x63\x6c\x61\x73\163\x3d\42\x6d\x6f\x5f\163\x61\x6d\x6c\137\x73\x70\137\146\157\x6e\164\x5f\146\x6f\x72\x5f\x68\x65\x61\x64\151\x6e\x67\x22\x3e\x53\151\x67\156\x69\156\40\123\145\x74\x74\151\x6e\147\x73\74\x2f\144\151\x76\x3e\x3c\x68\x72\76\x3c\142\162\76");
        $form["\x6d\157\x5f\163\141\x6d\x6c\137\x73\151\x6e\x67\156\x69\156\x5f\163\x65\x74\164\x69\x6e\x67\x73"]["\155\x69\156\151\157\162\x61\x6e\147\x65\137\x73\x61\155\154\x5f\154\x6f\141\x64\137\165\x73\145\162"] = array("\x23\x74\x79\x70\145" => "\x72\x61\x64\x69\157\x73", "\x23\164\151\164\154\x65" => t("\123\145\141\162\x63\x68\40\x55\163\x65\162\x20\x69\156\x20\x44\162\x75\x70\141\154\x20\165\x73\x69\x6e\147\x3a"), "\x23\144\145\163\x63\162\x69\x70\x74\x69\157\x6e" => t("\124\x68\x65\x20\x75\x73\145\x72\40\x77\151\154\154\40\x62\145\40\x73\x65\x61\x72\143\150\x65\144\x20\x75\x73\151\156\x67\40\164\x68\x69\163\40\x61\164\x74\x72\151\142\165\x74\145\x2e"), "\x23\x64\x65\x66\x61\165\x6c\164\137\166\141\154\x75\x65" => $y8->get("\155\x69\156\x69\157\x72\141\x6e\x67\x65\137\163\x61\x6d\154\137\x6c\x6f\x61\144\137\x75\x73\145\162"), "\43\157\x70\164\151\157\x6e\x73" => array(t("\125\163\x65\162\156\x61\x6d\x65"), t("\105\x6d\x61\151\x6c\x20\x41\144\x64\162\x65\163\x73")), "\43\163\165\x66\146\151\x78" => "\x3c\x62\x72\76");
        $form["\155\157\137\163\141\x6d\154\137\x73\151\156\x67\156\x69\x6e\137\163\145\164\x74\x69\x6e\x67\163"]["\x6d\151\x6e\151\157\x72\x61\x6e\x67\145\x5f\163\141\x6d\154\137\144\x69\x73\x61\x62\154\x65\137\141\165\164\x6f\143\x72\x65\141\x74\145\x5f\x75\163\145\x72\163"] = array("\x23\164\171\160\145" => "\143\150\x65\143\153\142\157\x78", "\43\x74\151\x74\154\145" => t("\x43\x68\x65\143\153\40\164\x68\x69\163\x20\x6f\160\164\x69\x6f\156\x20\x69\x66\x20\171\x6f\165\40\167\141\156\164\x20\164\x6f\x20\x64\151\163\x61\x62\154\145\40\74\x62\76\141\x75\x74\x6f\40\x63\162\x65\x61\x74\151\x6f\156\x3c\57\142\76\x20\157\x66\x20\165\x73\145\x72\x73\40\151\x66\x20\x75\163\145\162\40\x64\x6f\145\x73\40\x6e\x6f\164\x20\x65\170\151\x73\x74\x2e"), "\x23\144\x65\x66\x61\x75\x6c\x74\137\x76\141\x6c\165\x65" => $y8->get("\155\151\156\x69\157\x72\141\x6e\147\x65\137\163\141\155\x6c\137\144\x69\163\141\142\x6c\145\137\x61\x75\164\x6f\143\x72\145\141\x74\145\137\x75\x73\145\162\x73"), "\43\x64\145\x73\143\x72\x69\x70\x74\x69\x6f\x6e" => t("\x3c\142\x3e\116\x6f\164\x65\40\x3a\74\57\x62\x3e\40\111\x66\x20\x79\x6f\165\x20\145\156\141\x62\154\145\x20\x74\x68\151\x73\40\x66\145\141\x74\x75\x72\x65\40\x6e\x65\167\40\165\163\x65\162\40\167\x6f\x6e\x74\x20\142\145\40\143\x72\145\141\x74\x65\x64\x2c\x20\157\x6e\154\171\x20\145\170\x69\x73\x74\x69\x6e\x67\x20\165\163\x65\x72\163\40\143\x61\156\40\154\157\147\x69\156\40\165\x73\151\156\x67\x20\x53\123\117\56\74\x62\162\x3e\74\142\162\76"), "\43\144\x69\x73\x61\142\x6c\x65\144" => $C1);
        $form["\x6d\x6f\137\163\x61\155\x6c\137\x73\151\x6e\147\156\x69\156\137\163\x65\x74\x74\x69\156\147\163"]["\x6d\x69\x6e\x69\157\x72\141\x6e\x67\145\x5f\x73\141\155\154\137\x66\x6f\162\143\x65\x5f\141\x75\x74\150"] = array("\43\x74\171\160\145" => "\x63\150\145\x63\153\142\x6f\x78", "\x23\x74\151\x74\154\145" => t("\x50\x72\157\x74\145\143\164\40\x77\145\x62\x73\x69\164\x65\x20\141\x67\x61\151\x6e\163\x74\x20\x61\x6e\157\x6e\x79\155\x6f\165\163\40\x61\x63\143\x65\x73\x73"), "\43\144\145\146\x61\165\x6c\x74\x5f\x76\x61\x6c\165\x65" => $y8->get("\x6d\151\156\x69\157\162\141\156\147\x65\137\x73\x61\155\154\x5f\x66\157\x72\x63\145\137\141\165\x74\150"), "\x23\x64\145\x73\x63\x72\x69\x70\164\151\157\156" => t("\74\142\x3e\116\x6f\164\145\x3a\x20\74\x2f\142\76\x55\163\145\162\163\x20\x77\151\154\154\40\142\x65\40\162\x65\144\151\x72\145\x63\164\145\x64\x20\x74\157\40\x79\x6f\165\x72\40\x49\x64\x50\x20\x66\157\x72\x20\154\157\x67\151\156\x20\151\156\x20\143\141\x73\145\40\165\x73\145\162\x20\151\x73\x20\156\x6f\164\x20\154\157\x67\147\x65\x64\40\151\156\x20\141\156\x64\40\x74\162\151\x65\x73\x20\164\x6f\40\141\x63\143\x65\x73\x73\40\x77\x65\x62\x73\151\x74\x65\x2e\x3c\x62\162\x3e\74\x62\162\76"), "\x23\144\151\x73\141\x62\154\x65\144" => $C1);
        $form["\155\157\137\163\141\x6d\154\137\163\151\x6e\x67\156\151\156\137\163\145\164\164\151\156\147\x73"]["\155\x69\156\x69\x6f\x72\141\x6e\x67\145\137\x73\141\x6d\154\137\x61\165\164\x6f\137\162\145\144\x69\x72\145\143\x74"] = array("\x23\x74\171\160\145" => "\x63\150\x65\143\153\142\157\x78", "\x23\x74\151\164\154\x65" => t("\x43\150\x65\143\x6b\40\x74\x68\151\x73\40\157\x70\164\151\157\x6e\40\151\x66\x20\171\x6f\165\40\x77\141\156\164\x20\x74\x6f\x20\74\x62\x3e\141\x75\164\157\x20\x72\x65\144\151\162\145\143\164\x20\x74\x68\x65\x20\165\x73\145\162\x20\x74\157\x20\111\x64\x50\x3c\x2f\x62\x3e"), "\43\x64\x65\146\x61\165\x6c\x74\137\x76\141\x6c\165\x65" => $y8->get("\155\x69\156\151\157\162\141\x6e\147\145\x5f\x73\141\x6d\154\137\141\165\164\157\137\162\145\144\x69\x72\x65\143\x74\137\164\157\x5f\151\x64\160"), "\43\144\145\163\x63\162\x69\x70\x74\151\x6f\156" => t("\x3c\x62\x3e\x4e\157\164\x65\72\40\x3c\57\142\76\x55\163\x65\162\x73\40\167\x69\154\154\x20\x62\145\40\162\145\x64\151\x72\x65\x63\x74\x65\144\x20\164\157\40\171\x6f\165\x72\40\x49\144\120\40\x66\x6f\x72\x20\x6c\157\x67\151\x6e\40\167\x68\145\x6e\x20\164\x68\x65\x20\154\x6f\x67\151\x6e\40\x70\x61\147\x65\x20\151\x73\40\x61\x63\143\x65\163\x73\x65\x64\x2e\x3c\x62\x72\x3e\x3c\x62\x72\x3e"), "\x23\x64\151\163\x61\142\x6c\145\144" => $C1);
        $cU = is_null($y8->get("\155\151\x6e\151\157\x72\x61\156\x67\x65\x5f\142\141\143\153\x64\x6f\x6f\162\137\x71\165\145\x72\x79")) ? "\x66\x61\x6c\x73\145" : $y8->get("\155\x69\x6e\151\157\x72\141\156\x67\145\137\x62\141\143\x6b\x64\x6f\x6f\162\x5f\x71\x75\145\x72\x79");
        $q4 = $C1 == FALSE ? $u_ . "\57\165\163\145\162\57\154\x6f\147\x69\x6e\77\163\141\x6d\154\137\154\157\x67\x69\x6e\x3d" . $cU . "\x3c\x61\40\x20\x69\144\x3d\42\155\157\137\163\141\x6d\154\137\145\144\151\164\x5f\142\141\143\153\x64\x6f\x6f\162\x22\40\143\x6c\141\x73\x73\75\x22\155\157\x5f\x73\141\155\154\137\x62\x74\x6e\x20\x6d\157\137\x73\141\x6d\x6c\x5f\142\x74\x6e\55\160\162\x69\x6d\x61\162\171\40\155\x6f\x5f\163\x61\x6d\154\137\x62\x74\x6e\55\163\x6d\x22\76\105\x64\x69\164\74\x2f\x61\76" : "\x52\145\x67\x69\163\164\145\162\x2f\114\157\x67\151\156\40\167\x69\164\150\40\x6d\151\156\151\x4f\162\x61\x6e\147\145\40\x74\157\40\x73\145\145\x20\164\x68\145\x20\125\x52\114\x2e";
        $form["\155\x6f\137\163\x61\155\x6c\x5f\163\151\x6e\147\156\x69\156\137\163\145\x74\164\x69\x6e\147\163"]["\x6d\151\x6e\151\x6f\162\141\x6e\147\145\137\163\x61\155\x6c\x5f\x65\156\141\142\x6c\145\x5f\x62\x61\x63\153\144\157\x6f\x72"] = array("\43\x74\x79\x70\145" => "\143\150\x65\x63\x6b\142\157\170", "\x23\164\x69\x74\x6c\145" => t("\103\150\x65\x63\153\x20\x74\x68\151\x73\x20\x6f\160\164\x69\x6f\156\40\151\146\40\x79\x6f\x75\40\167\141\156\x74\x20\164\x6f\x20\x65\x6e\141\142\154\x65\x20\74\x62\x3e\x62\141\x63\x6b\x64\157\157\162\x20\x6c\157\147\151\156\74\57\142\x3e"), "\x23\x64\x65\146\x61\x75\x6c\164\137\166\141\154\x75\x65" => $y8->get("\x6d\x69\x6e\x69\157\162\x61\x6e\x67\x65\x5f\163\x61\x6d\154\x5f\x65\x6e\141\142\x6c\x65\x5f\142\x61\x63\153\x64\157\x6f\x72"), "\x23\144\x65\163\143\x72\x69\160\164\x69\x6f\x6e" => t("\x3c\142\x3e\116\157\164\145\72\x20\x3c\x2f\142\x3e\x43\x68\x65\143\153\151\156\x67\40\164\x68\x69\x73\x20\157\160\164\x69\157\x6e\x20\x3c\142\x3e\143\162\x65\x61\164\145\163\40\141\x20\142\x61\143\x6b\x64\x6f\x6f\x72\40\164\157\40\154\157\x67\151\x6e\40\164\157\x20\x79\x6f\x75\x72\40\127\x65\x62\163\x69\x74\x65\x20\165\x73\151\156\147\x20\104\x72\x75\160\141\x6c\40\143\162\145\x64\145\x6e\164\151\x61\x6c\163\74\x2f\x62\76\74\x62\162\x3e\xd\xa\40\x20\40\x20\x20\40\40\x20\40\40\x20\40\40\40\x20\x20\40\x20\151\156\143\141\x73\145\x20\x79\157\x75\40\x67\x65\x74\x20\x6c\157\143\153\x65\144\x20\157\x75\x74\x20\x6f\x66\40\171\x6f\x75\162\40\x49\144\120\56\74\142\162\76\74\142\76\116\157\x74\x65\x20\144\157\x77\x6e\40\x74\x68\x69\163\40\142\x61\x63\x6b\144\x6f\157\162\x20\125\122\114\x3a\40\x3c\x63\x6f\144\x65\76\74\141\40\151\144\x3d\42\x6d\x6f\137\163\141\x6d\x6c\x5f\142\x61\x63\153\144\x6f\x6f\162\137\165\x72\154\x22\76" . $q4 . "\x3c\x2f\141\x3e\74\57\142\x3e\74\57\143\157\144\x65\x3e\74\x62\x72\76\x3c\x62\x72\x3e"), "\43\x64\151\x73\x61\142\x6c\x65\x64" => $C1);
        $form["\155\x6f\137\x73\x61\x6d\x6c\137\163\x69\156\x67\156\151\156\x5f\163\145\164\164\151\x6e\147\163"]["\x6d\151\156\151\157\x72\x61\156\147\145\x5f\163\141\x6d\x6c\x5f\142\141\143\x6b\x64\157\x6f\162\x5f\164\145\x78\164\142\x6f\x78\x31"] = array("\43\160\x72\x65\146\x69\x78" => "\x3c\x74\141\x62\x6c\145\x20\163\164\171\154\x65\x3d\42\x77\x69\144\164\x68\x3a\61\x30\60\45\73\42\x20\151\x64\75\42\155\151\156\151\157\x72\x61\x6e\147\x65\x5f\x73\141\155\154\x5f\x62\x61\143\153\x64\x6f\x6f\162\x5f\164\141\x62\x6c\x65\x22\x20\x68\x69\x64\144\145\156\76\x3c\x74\x72\x3e\74\x74\x64\76\74\x64\x69\x76\40\x63\x6c\x61\x73\163\x3d\x22\x6d\x6f\x5f\142\x61\143\153\x64\157\157\x72\42\x20\151\x64\x3d\42\x62\141\x63\153\x64\157\x6f\162\x22\x3e\74\143\x6f\x64\x65\x3e\74\141\76\74\x73\x74\162\157\156\147\40\x69\x64\x3d\42\x6d\151\x6e\151\x6f\x72\141\x6e\147\x65\x5f\163\141\155\x6c\x5f\x62\141\143\153\x64\x6f\157\x72\137\x62\141\x73\x65\137\x75\162\x6c\137\164\x6f\x5f\141\x70\160\145\156\x64\x22\x3e" . $u_ . "\x2f\165\163\145\162\57\x6c\157\147\x69\x6e\x3f\163\141\x6d\x6c\137\x6c\x6f\147\151\x6e\x3d\74\x2f\x73\x74\162\x6f\156\x67\76\x3c\x2f\x61\76\74\x2f\x63\x6f\144\x65\76", "\x23\164\x79\x70\x65" => "\x74\145\x78\x74\x66\151\145\x6c\144", "\43\x69\x64" => "\155\151\x6e\x69\157\162\141\x6e\x67\x65\137\x73\x61\155\154\x5f\142\x61\143\x6b\144\x6f\x6f\162\137\x74\x65\x78\164\x62\157\x78\x31", "\x23\144\x65\146\141\165\x6c\x74\x5f\x76\141\x6c\x75\145" => $cU, "\43\x73\x75\x66\x66\151\x78" => "\x3c\57\x64\x69\x76\76\74\57\164\x64\76\x3c\x2f\x74\x72\76\74\57\x74\x61\x62\154\x65\76");
        $form["\x6d\157\x5f\163\x61\x6d\154\137\163\x69\x6e\147\156\151\156\137\163\145\x74\x74\x69\156\x67\163"]["\x6d\x69\156\x69\157\162\141\x6e\x67\145\x5f\163\141\x6d\154\137\x64\145\x66\141\x75\x6c\164\x5f\162\x65\154\141\171\x73\x74\141\164\x65"] = array("\x23\164\171\x70\x65" => "\164\x65\x78\164\x66\x69\145\154\x64", "\43\164\151\x74\154\x65" => t("\104\145\x66\x61\165\154\x74\40\122\x65\x64\x69\162\x65\x63\x74\x20\x55\x52\114\x20\x61\146\x74\x65\162\40\x6c\x6f\147\x69\x6e"), "\43\x64\145\146\x61\x75\154\x74\137\166\x61\x6c\165\x65" => $y8->get("\155\x69\156\151\157\162\141\156\147\145\x5f\x73\141\155\154\x5f\144\145\x66\141\x75\x6c\164\x5f\x72\145\x6c\x61\x79\163\x74\x61\x74\x65"), "\43\x61\x74\x74\x72\151\x62\165\164\x65\x73" => array("\163\164\x79\x6c\x65" => "\167\151\x64\x74\150\72\70\60\45", "\x70\154\x61\x63\x65\x68\x6f\154\144\145\x72" => "\x45\156\x74\145\162\40\104\145\146\141\165\x6c\164\40\122\145\x64\x69\x72\145\143\164\x20\125\x52\x4c"), "\43\144\151\x73\x61\x62\154\145\144" => $C1, "\43\144\145\x73\143\162\x69\x70\x74\151\157\156" => t("\x3c\142\x3e\116\x6f\x74\x65\72\x20\74\x2f\142\76\x45\156\x74\145\162\40\x74\150\x65\40\146\165\154\x6c\40\x55\x52\114\40\151\x6e\143\154\x75\x64\151\156\x67\x20\x74\x68\145\40\142\141\x73\x65\x20\x70\141\x74\150\x20\157\146\40\x74\150\x65\40\167\145\142\x73\151\x74\145\56\x20\x46\157\162\x20\x45\170\141\x6d\160\x6c\145\x3a\x3c\151\76\74\x75\x3e\150\x74\164\x70\163\x3a\57\x2f\x65\x78\x61\155\160\x6c\x65\x2e\143\157\155\x2f\x70\162\x6f\x66\151\x6c\x65\74\x2f\165\76\x3c\x2f\151\x3e\x20"), "\43\x73\165\146\x66\x69\170" => "\x3c\142\x72\x3e");
        $form["\155\x6f\x5f\x73\x61\155\154\137\x73\151\156\x67\x6e\151\x6e\x5f\x73\145\164\x74\x69\x6e\147\163"]["\x6d\151\156\151\x6f\162\x61\x6e\147\145\137\x73\141\155\x6c\x5f\144\145\146\141\x75\154\164\137\162\x65\144\151\x72\145\x63\164\x5f\x75\x72\x6c\x5f\x61\146\x74\145\162\137\154\x6f\147\x6f\165\x74"] = array("\x23\x74\171\x70\x65" => "\x74\x65\x78\164\146\151\145\154\144", "\x23\164\x69\164\x6c\x65" => t("\104\145\146\141\x75\154\x74\x20\x52\x65\144\151\x72\x65\x63\x74\40\x55\122\x4c\40\x61\146\164\x65\x72\x20\x6c\157\x67\157\x75\164"), "\43\x64\145\x66\141\165\154\x74\x5f\x76\141\154\165\x65" => $y8->get("\155\x69\x6e\151\157\162\141\156\147\x65\137\x73\x61\155\x6c\137\x64\x65\146\x61\x75\154\164\x5f\162\x65\x64\x69\162\x65\x63\164\137\165\x72\x6c\x5f\x61\146\x74\x65\162\x5f\x6c\x6f\147\157\165\164"), "\43\141\164\x74\x72\x69\142\x75\x74\x65\x73" => array("\x73\164\171\154\x65" => "\167\x69\x64\164\150\x3a\70\x30\45", "\160\154\x61\143\x65\150\x6f\x6c\x64\145\x72" => "\105\156\164\x65\162\x20\x44\x65\x66\141\x75\154\164\x20\122\145\144\151\x72\145\x63\x74\40\x55\x52\114\40\x61\146\164\x65\162\40\154\157\x67\157\165\x74"), "\43\x64\x69\x73\x61\142\154\x65\144" => $C1, "\43\144\x65\163\143\x72\151\x70\x74\x69\157\156" => t("\x3c\142\x3e\x4e\x6f\x74\x65\x3a\40\x3c\x2f\142\x3e\105\x6e\164\145\162\40\x74\150\x65\x20\x70\x61\x74\150\40\145\170\x63\x6c\165\144\151\x6e\147\x20\164\x68\145\40\x62\141\163\145\x20\x70\141\164\x68\x20\x6f\x66\x20\164\x68\145\40\167\145\x62\x73\151\x74\x65\56"), "\x23\x73\165\x66\146\x69\170" => "\74\x62\162\x3e");
        $DZ = $C1 || MiniorangeSAMLConstants::PLUGIN_VERSION != MiniorangeSAMLConstants::ENTERPRISE_VERSION;
        $XZ = MiniorangeSAMLConstants::PLUGIN_VERSION != MiniorangeSAMLConstants::ENTERPRISE_VERSION ? "\x3c\x61\40\150\162\x65\x66\75\x22" . $base_url . MiniorangeSAMLConstants::LICENSING_TAB_URL . "\42\x3e\133\105\x6e\164\x65\162\x70\x72\151\x73\145\x5d\x3c\57\x61\76" : '';
        $form["\x6d\x6f\x5f\x73\x61\x6d\x6c\137\x73\x69\x6e\x67\x6e\x69\156\x5f\x73\145\x74\x74\151\x6e\147\x73"]["\x6d\151\156\x69\157\162\141\x6e\147\x65\137\163\141\155\x6c\137\x64\x6f\x6d\141\x69\x6e\x5f\162\x65\163\164\162\151\x63\164\151\157\x6e\137\143\150\x65\x63\x6b\142\157\170"] = array("\43\164\171\160\145" => "\143\150\145\x63\153\x62\x6f\170", "\43\164\x69\164\x6c\x65" => t("\x43\150\x65\143\153\40\x74\150\151\x73\40\x6f\x70\164\151\157\x6e\x20\151\146\40\171\157\x75\x20\167\141\156\x74\40\40\x3c\x62\76\104\157\155\141\x69\x6e\x20\122\145\163\164\x72\151\143\x74\151\157\x6e\x20" . $XZ . "\x3c\57\142\x3e"), "\x23\144\x69\x73\x61\x62\154\145\x64" => $DZ, "\43\144\145\146\x61\165\154\x74\137\x76\141\x6c\165\x65" => $y8->get("\155\x69\156\151\157\x72\x61\156\147\145\x5f\x73\x61\155\154\x5f\x65\156\141\142\x6c\145\x5f\x64\x6f\155\141\151\156\x5f\162\145\x73\164\x72\151\x63\164\151\x6f\156"));
        $form["\x6d\157\x5f\163\x61\x6d\154\x5f\163\x69\x6e\x67\156\x69\x6e\x5f\163\145\164\164\x69\156\147\x73"]["\x6d\151\156\x69\157\162\141\156\147\145\x5f\163\x61\x6d\154\x5f\x73\145\x74\137\157\x66\137\162\141\144\x69\x6f\142\165\x74\x74\157\156\163"] = array("\x23\164\171\x70\145" => "\146\x69\x65\x6c\x64\163\x65\x74", "\x23\163\164\x61\x74\x65\163" => array("\x76\x69\163\x69\142\154\145" => array("\x3a\151\x6e\160\x75\164\x5b\156\141\155\x65\75\x22\x6d\151\156\x69\x6f\162\141\x6e\147\145\137\163\x61\x6d\154\137\144\x6f\x6d\141\x69\156\x5f\x72\x65\163\164\162\151\143\164\151\157\156\x5f\143\150\x65\143\x6b\x62\157\170\42\x5d" => array("\143\x68\145\x63\x6b\145\144" => MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION))));
        $form["\155\157\137\163\x61\x6d\x6c\x5f\x73\151\x6e\x67\x6e\x69\x6e\137\x73\145\x74\164\151\156\147\x73"]["\155\151\156\151\157\x72\141\x6e\x67\x65\x5f\x73\141\155\x6c\x5f\x73\x65\x74\x5f\157\x66\137\x72\x61\144\151\x6f\x62\x75\164\x74\157\x6e\163"]["\x6d\x69\156\x69\x6f\x72\x61\156\147\145\x5f\x73\x61\155\154\137\141\x6c\x6c\157\167\137\157\x72\137\x62\154\157\143\x6b\x5f\144\157\x6d\141\151\156\x73"] = array("\x23\x74\x79\x70\x65" => "\162\x61\x64\151\x6f\x73", "\x23\x6d\x61\x78\x6c\145\x6e\147\164\x68" => 5, "\43\157\x70\x74\x69\x6f\x6e\x73" => array("\167\x68\151\x74\x65" => t("\111\x20\x77\x61\156\x74\40\x74\157\x20\x61\154\x6c\157\167\x20\157\x6e\154\171\40\x73\x6f\x6d\x65\40\157\146\x20\164\150\x65\x20\144\x6f\155\x61\x69\x6e\163"), "\142\x6c\x61\143\153" => t("\111\x20\x77\x61\156\x74\x20\164\157\40\x62\x6c\x6f\143\x6b\x20\x73\157\x6d\145\x20\157\x66\40\x74\150\145\40\144\157\155\141\151\156\163")), "\x23\x64\x65\x66\x61\165\154\164\x5f\166\141\154\165\145" => is_null($y8->get("\155\x69\156\x69\157\x72\141\x6e\147\x65\x5f\x73\x61\155\x6c\x5f\144\157\x6d\141\151\x6e\x73\x5f\141\162\145\137\x77\150\x69\x74\145\137\157\x72\x5f\142\154\141\143\153")) ? "\167\x68\151\x74\x65" : $y8->get("\x6d\151\156\151\x6f\x72\141\x6e\147\145\x5f\x73\x61\155\154\137\144\157\x6d\141\x69\156\x73\137\x61\x72\145\x5f\x77\150\x69\164\x65\137\157\x72\137\142\154\x61\x63\x6b"), "\x23\144\x69\x73\141\x62\x6c\x65\x64" => $DZ);
        $form["\x6d\157\x5f\x73\x61\155\154\x5f\163\x69\156\x67\x6e\x69\x6e\x5f\x73\145\x74\164\151\156\x67\x73"]["\155\x69\x6e\x69\x6f\162\141\x6e\x67\x65\x5f\163\x61\x6d\x6c\x5f\x73\x65\164\x5f\x6f\146\137\162\x61\x64\151\157\x62\x75\x74\x74\x6f\156\x73"]["\155\x69\x6e\151\x6f\x72\141\x6e\147\145\137\163\141\x6d\154\137\144\157\x6d\x61\x69\156\x73"] = array("\43\x74\x79\x70\145" => "\x74\x65\170\x74\x61\x72\145\x61", "\43\164\151\164\154\x65" => t(''), "\43\141\164\164\162\x69\x62\165\x74\145\163" => array("\163\164\x79\x6c\x65" => "\x77\x69\x64\164\150\x3a\x38\60\x25\x3b\x20\x68\x65\x69\147\x68\164\x3a\61\60\60\x70\170\73", "\x70\154\x61\x63\x65\150\x6f\154\x64\x65\x72" => "\x45\x6e\164\145\x72\x20\163\145\x6d\x69\143\157\154\x6f\156\50\73\x29\x20\163\x65\x70\x61\x72\141\x74\x65\x64\40\x64\x6f\155\x61\151\156\163\x20\x28\105\147\x2e\x20\170\170\170\170\x2e\x63\x6f\x6d\73\x20\x78\170\x78\x78\56\143\x6f\155\51"), "\43\144\151\163\x61\142\154\x65\x64" => $DZ, "\43\x64\x65\x66\x61\x75\154\164\x5f\166\x61\x6c\x75\x65" => is_null($y8->get("\x6d\151\156\151\157\162\x61\156\x67\x65\137\163\x61\x6d\x6c\x5f\144\x6f\x6d\x61\x69\156\x73")) ? '' : $y8->get("\x6d\151\x6e\151\x6f\x72\141\x6e\x67\145\x5f\x73\x61\x6d\x6c\137\144\157\x6d\x61\x69\156\163"), "\43\163\x75\x66\x66\151\x78" => "\x3c\x62\162\76");
        $form["\155\x6f\x5f\x73\x61\155\154\x5f\163\151\x6e\147\156\151\156\x5f\x73\145\164\164\x69\x6e\147\163"]["\x6d\x69\x6e\x69\157\x72\x61\x6e\x67\145\137\163\141\x6d\x6c\137\x61\x74\164\x72\x69\x62\165\164\x65\x5f\x62\x61\163\145\144\137\x72\x65\163\164\x72\151\143\164\151\x6f\156"] = array("\43\x74\x79\x70\x65" => "\x63\150\145\143\x6b\x62\157\x78", "\43\x74\151\x74\x6c\x65" => t("\x41\154\154\x6f\167\x20\x53\123\117\x20\x6c\x6f\x67\151\x6e\x20\x20\x62\141\x73\x65\x64\x20\157\156\40\x61\164\x74\162\151\x62\165\x74\145\x73" . $XZ . "\x3c\x2f\142\76"), "\x23\x64\151\x73\x61\x62\x6c\x65\144" => $DZ, "\43\x64\145\x66\141\165\154\164\137\x76\x61\x6c\x75\145" => $y8->get("\155\151\x6e\x69\x6f\162\141\x6e\147\145\x5f\163\141\x6d\x6c\137\x65\x6e\x61\142\154\x65\137\x61\x74\x74\162\x69\x62\x75\164\x65\x5f\162\x65\x73\x74\162\x69\143\x74\151\157\156"));
        $form["\x6d\157\137\163\141\x6d\x6c\x5f\x73\151\156\147\x6e\151\x6e\x5f\163\145\x74\x74\x69\x6e\x67\x73"]["\155\151\x6e\151\x6f\x72\x61\156\x67\x65\x5f\163\141\155\154\x5f\x61\164\x74\x72\x69\142\165\164\145\137\x66\151\x65\154\x64\163\145\164"] = array("\43\164\x79\x70\x65" => "\x66\x69\x65\x6c\x64\163\145\164", "\43\163\x74\141\164\x65\x73" => array("\x76\x69\163\151\142\154\145" => array("\72\151\156\x70\x75\164\x5b\156\141\x6d\145\75\x22\155\151\156\x69\x6f\162\141\156\147\145\x5f\x73\x61\x6d\154\137\141\x74\x74\x72\x69\142\165\x74\145\137\142\141\x73\145\144\137\x72\x65\x73\x74\x72\151\x63\164\151\x6f\x6e\x22\x5d" => array("\x63\x68\x65\143\153\x65\144" => MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION))));
        $form["\x6d\157\137\x73\141\x6d\x6c\x5f\163\151\156\x67\156\x69\156\137\163\x65\164\x74\151\156\x67\163"]["\155\x69\156\x69\x6f\x72\141\x6e\x67\x65\137\163\141\155\x6c\x5f\141\x74\164\162\151\x62\x75\x74\145\137\x66\x69\x65\154\144\x73\145\164"]["\x6d\151\x6e\x69\157\x72\x61\x6e\147\x65\137\163\141\155\154\137\141\164\x74\x72\151\x62\x75\164\x65\x5f\x62\x61\x73\x65\x64\x5f\x72\x75\154\145\163"] = array("\43\x74\x79\160\x65" => "\164\145\170\x74\x61\162\x65\x61", "\43\164\x69\164\x6c\x65" => t("\x52\x75\x6c\145\x73\40\x6f\146\40\x61\164\x74\162\x69\x62\165\x74\145\40\x62\141\163\145\x64\x20\154\x6f\x67\151\156\56\x20\74\x62\x3e\125\163\145\x72\40\155\x75\163\x74\40\x70\x61\163\x73\40\x61\x74\40\154\x65\141\163\x74\x20\157\156\x65\x20\162\165\x6c\145\x20\x74\157\40\x70\x65\x72\x66\x6f\x72\x6d\40\123\123\x4f\40\154\x6f\x67\x69\x6e\x3c\x2f\x62\76"), "\43\144\151\x73\x61\x62\x6c\145\144" => $DZ, "\43\144\145\146\x61\165\x6c\x74\137\x76\141\x6c\x75\145" => $y8->get("\x6d\151\156\x69\157\x72\141\x6e\x67\145\x5f\163\141\155\154\x5f\x61\x74\164\162\151\x62\165\x74\145\137\x62\141\163\x65\144\x5f\162\x75\154\145\x73"), "\x23\x64\x65\x73\x63\x72\151\160\164\x69\x6f\x6e" => "\40\105\156\164\x65\x72\x20\157\x6e\145\40\x72\x75\154\x65\40\160\x65\x72\x20\x6c\151\x6e\x65\54\40\x69\156\40\164\150\145\40\146\157\162\x6d\141\164\72\74\142\x3e\x61\164\x74\162\x69\142\165\x74\145\x20\156\x61\x6d\x65\174\x61\x74\x74\x72\151\x62\165\164\x65\x20\x76\141\x6c\165\145\x7c\157\x70\145\x72\x61\x74\157\x72\x3c\x2f\142\x3e\74\142\162\76\xd\12\40\x20\40\40\40\x20\40\x20\40\40\40\x20\40\x20\x20\x20\x20\x20\x20\x20\40\40\x20\40\x3c\142\x3e\x4e\157\164\x65\x3a\55\x3c\57\142\x3e\x54\150\x65\x20\101\x74\164\x72\151\142\165\x74\145\40\x76\141\x6c\165\145\x73\40\x61\162\x65\x20\143\141\163\x65\x20\x73\145\156\163\151\164\151\166\145\40\x61\x6e\144\x20\164\x68\x65\x20\160\157\x73\x73\151\142\x6c\x65\x20\157\160\145\x72\x61\164\157\162\x73\x20\141\162\145\40\74\142\x3e\x73\164\x61\x72\x74\x73\137\167\151\x74\x68\74\x2f\142\x3e\x2c\74\142\76\143\x6f\x6e\x74\x61\151\x6e\x73\74\57\x62\76\x2c\x3c\142\76\145\161\x75\141\x6c\137\164\x6f\74\x2f\142\x3e\x2c\74\x62\x3e\145\156\x64\163\137\x77\x69\x74\x68\74\x2f\x62\x3e");
        $form["\x6d\x6f\137\x73\141\x6d\x6c\x5f\163\151\x6e\x67\156\151\156\x5f\163\145\164\x74\151\156\147\x73"]["\x6d\x69\x6e\x69\157\x72\x61\156\x67\145\x5f\163\141\x6d\154\137\162\x65\163\164\x72\x69\143\164\137\162\x65\x64\151\x72\x65\x63\164\x5f\157\x75\164\x73\151\144\x65\x5f\x64\x6f\x6d\141\x69\x6e"] = array("\x23\x74\171\x70\x65" => "\x63\150\145\x63\x6b\142\x6f\x78", "\x23\164\x69\164\x6c\145" => t("\x43\150\145\x63\x6b\40\164\x68\151\x73\40\x6f\160\x74\x69\157\x6e\x20\151\146\40\x79\x6f\165\40\x77\141\156\164\40\164\157\40\162\145\x73\x74\162\151\x63\164\40\x72\x65\x64\151\162\145\143\164\x20\141\x66\x74\145\162\x20\123\123\117\x20\164\157\40\157\x75\164\163\x69\x64\145\40\x64\157\x6d\141\x69\x6e\x2e\x20\40\x3c\142\x3e" . $XZ . "\74\x2f\x62\76"), "\43\144\151\163\141\142\154\x65\144" => $DZ, "\x23\x64\x65\x66\x61\165\154\x74\137\166\141\x6c\165\x65" => $y8->get("\x6d\151\156\151\157\x72\141\x6e\x67\x65\137\x73\x61\x6d\154\137\x72\145\163\x74\x72\x69\143\x74\x5f\162\145\144\151\162\x65\143\164\137\x6f\x75\164\163\151\x64\145\x5f\144\157\x6d\141\151\x6e"));
        $form["\155\x6f\137\x73\141\x6d\x6c\137\163\151\156\147\156\151\x6e\137\163\145\164\x74\151\156\x67\163"]["\155\x69\x6e\151\157\162\141\156\147\145\137\x73\x61\155\x6c\137\x77\x68\151\x74\x65\154\x69\x73\164\x5f\x66\x69\145\x6c\144\x73\145\164"] = array("\43\x74\171\160\145" => "\x66\x69\145\x6c\144\163\x65\164", "\43\x73\x74\141\x74\145\x73" => array("\x76\x69\163\151\142\x6c\145" => array("\x3a\x69\x6e\x70\x75\x74\133\x6e\x61\155\145\75\42\x6d\x69\156\151\157\162\141\x6e\x67\x65\137\x73\x61\x6d\x6c\137\162\145\163\x74\x72\151\x63\x74\137\x72\145\144\x69\x72\145\x63\164\x5f\157\165\164\163\151\144\145\x5f\x64\157\155\x61\x69\156\42\x5d" => array("\x63\150\x65\x63\x6b\145\x64" => MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION))));
        $form["\155\157\x5f\163\x61\x6d\154\x5f\x73\151\x6e\x67\156\x69\156\137\163\145\164\x74\x69\x6e\x67\x73"]["\155\151\x6e\x69\x6f\x72\141\x6e\x67\145\x5f\x73\x61\x6d\154\137\167\x68\x69\164\145\154\x69\163\x74\137\x66\x69\145\x6c\144\x73\145\x74"]["\155\x69\x6e\151\157\x72\141\x6e\147\x65\x5f\163\x61\155\154\x5f\x77\150\x69\164\x65\154\151\x73\x74\x5f\x64\x6f\x6d\141\151\156\163"] = array("\x23\x74\x79\x70\x65" => "\x74\145\x78\x74\141\162\x65\141", "\x23\164\x69\x74\x6c\145" => t("\127\150\x69\x74\145\154\151\x73\x74\40\104\157\155\x61\x69\156\x73"), "\x23\x61\164\x74\162\x69\x62\x75\x74\145\163" => array("\x73\164\x79\x6c\145" => "\x77\x69\x64\x74\150\72\x38\x30\45\x3b\40\x68\x65\151\147\150\x74\72\61\60\60\160\x78\73", "\x70\154\x61\143\x65\150\157\x6c\x64\x65\x72" => "\105\156\164\145\162\40\x73\x65\155\151\143\157\154\x6f\x6e\x28\x3b\x29\40\163\145\x70\x61\162\x61\x74\x65\144\x20\144\x6f\x6d\x61\x69\x6e\163\x20\50\105\147\56\x20\x78\170\x78\170\x2e\143\x6f\x6d\x3b\40\170\170\x78\x78\56\143\x6f\155\51"), "\x23\x64\x69\x73\141\142\x6c\145\144" => $DZ, "\43\x64\x65\x66\x61\x75\x6c\x74\x5f\x76\x61\x6c\x75\x65" => is_null($y8->get("\x6d\x69\x6e\x69\x6f\x72\141\x6e\147\x65\137\x73\141\x6d\154\137\x77\x68\x69\x74\145\x6c\151\x73\164\x5f\x64\x6f\155\141\151\x6e\163")) ? '' : $y8->get("\155\151\x6e\x69\x6f\162\141\x6e\x67\145\137\163\141\155\x6c\137\167\x68\x69\164\x65\154\151\163\x74\x5f\x64\x6f\x6d\x61\x69\156\163"), "\43\x73\x75\x66\x66\x69\170" => "\x3c\x62\x72\76", "\43\144\145\x73\143\162\x69\160\x74\151\x6f\x6e" => "\x45\x6e\x74\x65\x72\40\x73\145\x6d\151\x63\157\154\157\156\x28\x3b\x29\x20\163\145\x70\x61\x72\x61\164\x65\x64\40\x64\157\155\x61\151\156\163\x20\x28\105\147\x2e\x20\170\170\x78\170\56\x63\157\x6d\73\40\x78\x78\170\170\x2e\143\157\155\51\74\142\162\x3e\x3c\x62\x3e\116\157\x74\145\72\55\x3c\x2f\142\76\x20\124\150\145\40\x6d\x6f\144\x75\x6c\145\40\167\x69\154\154\40\x72\145\144\151\x72\145\143\x74\x20\164\157\40\164\150\x65\40\x72\x65\154\141\x79\x20\163\164\x61\164\x65\x20\x69\146\146\x20\164\x68\x65\40\x64\157\x6d\x61\151\156\40\x6f\x66\x20\x74\x68\145\40\x72\145\x6c\141\x79\x20\163\x74\x61\164\x65\40\x75\162\x6c\40\151\163\40\x77\x68\x69\x74\x65\x6c\x69\x73\164\145\x64\56");
        $form["\155\157\137\x73\x61\x6d\x6c\x5f\163\x69\x6e\x67\x6e\x69\x6e\137\163\145\x74\164\x69\x6e\x67\163"]["\x6d\151\156\151\157\x72\141\x6e\147\145\x5f\163\x61\155\x6c\137\147\x61\164\x65\x77\141\171\137\143\x6f\156\x66\x69\x67\x5f\163\165\142\155\x69\x74"] = array("\x23\160\x72\145\x66\151\x78" => "\74\x62\162\x3e", "\43\164\x79\x70\x65" => "\163\165\142\x6d\x69\x74", "\43\142\x75\x74\x74\x6f\156\x5f\x74\x79\160\x65" => "\160\162\151\155\141\x72\171", "\43\x69\x64" => "\x6d\x6f\137\163\x61\x6d\x6c\x5f\x73\x61\166\x65\x5f\x63\157\x6e\146\151\x67\x5f\142\164\156", "\43\166\141\x6c\x75\x65" => t("\123\x61\166\x65\x20\103\157\156\x66\x69\x67\x75\x72\141\x74\x69\x6f\156"), "\43\x64\151\x73\x61\142\x6c\x65\144" => $C1, "\43\x73\x75\146\x66\151\x78" => "\74\x2f\144\151\x76\x3e");
        Utilities::spConfigGuide($form, $form_state);
        return $form;
    }
    public function submitForm(array &$form, FormStateInterface $form_state)
    {
        $sA = $form_state->getValues();
        $MA = $sA["\155\151\156\151\157\x72\141\156\147\145\137\163\x61\x6d\154\x5f\144\x69\x73\x61\x62\x6c\145\x5f\141\x75\x74\157\x63\162\145\x61\164\x65\x5f\x75\163\x65\162\x73"];
        $Nw = $sA["\x6d\x69\156\x69\x6f\162\x61\156\x67\145\x5f\163\141\x6d\x6c\137\x66\x6f\162\143\x65\x5f\x61\x75\164\150"];
        $Px = $sA["\x6d\x69\x6e\x69\157\162\x61\x6e\x67\x65\137\x73\x61\155\x6c\x5f\141\x75\164\x6f\137\x72\x65\144\151\x72\x65\143\164"];
        $AI = $sA["\155\151\x6e\x69\157\162\x61\x6e\147\145\137\163\141\x6d\154\x5f\x65\156\141\x62\154\145\137\142\141\143\153\144\157\x6f\x72"];
        $H7 = $sA["\155\x69\156\x69\x6f\162\x61\x6e\147\145\137\x73\141\155\154\x5f\x64\145\x66\x61\x75\x6c\x74\x5f\162\145\154\141\171\163\164\141\x74\x65"];
        $D5 = $sA["\155\x69\x6e\151\x6f\162\141\156\x67\x65\x5f\x73\x61\155\154\x5f\142\x61\x63\153\144\157\x6f\162\x5f\164\145\170\164\142\x6f\x78\61"];
        $Og = $sA["\x6d\x69\156\x69\157\x72\141\156\147\145\x5f\163\x61\155\154\x5f\144\157\x6d\x61\x69\x6e\x5f\x72\x65\163\x74\162\151\x63\x74\151\157\x6e\x5f\143\150\x65\x63\153\142\157\170"];
        $u9 = $sA["\155\x69\156\151\x6f\162\141\x6e\147\145\137\163\141\x6d\x6c\137\141\154\x6c\x6f\x77\x5f\x6f\162\x5f\x62\154\157\143\x6b\x5f\144\157\155\x61\151\156\163"];
        $WG = $sA["\x6d\x69\156\x69\157\x72\141\156\x67\145\137\x73\x61\155\x6c\x5f\x64\x6f\x6d\141\x69\x6e\x73"];
        $Mr = $sA["\x6d\151\x6e\x69\157\162\x61\x6e\147\145\x5f\163\x61\x6d\x6c\137\x61\x74\x74\162\x69\142\165\164\x65\x5f\x62\x61\x73\x65\x64\137\x72\x65\x73\164\x72\x69\x63\x74\x69\x6f\x6e"];
        $aq = $sA["\155\x69\156\x69\157\162\141\156\147\x65\x5f\x73\x61\x6d\x6c\x5f\x61\x74\x74\x72\151\142\x75\164\145\x5f\x62\141\163\x65\x64\x5f\x72\x75\x6c\x65\163"];
        $Rh = $MA == 1;
        $rB = $Og == 1;
        $iL = $Nw == 1;
        $wE = $Px == 1;
        $wS = $AI == 1;
        $Mr = $Mr == 1;
        $QR = $sA["\155\151\156\x69\157\162\x61\x6e\x67\145\x5f\163\x61\x6d\154\137\x6c\157\141\144\x5f\165\163\145\x72"];
        $Bz = trim($sA["\155\x69\156\151\157\x72\x61\x6e\147\145\137\x73\141\155\x6c\x5f\144\145\x66\x61\x75\154\x74\137\x72\x65\x64\x69\162\x65\143\x74\x5f\x75\162\x6c\137\x61\146\164\145\162\137\x6c\x6f\x67\157\x75\164"]);
        $Mt = $sA["\x6d\151\x6e\151\x6f\162\141\x6e\x67\145\x5f\x73\x61\x6d\154\137\x72\145\163\164\x72\x69\x63\x74\137\x72\145\144\x69\162\145\143\164\x5f\157\x75\164\x73\x69\144\x65\137\x64\x6f\155\x61\151\x6e"];
        $Mf = $sA["\155\151\156\151\x6f\162\x61\156\147\x65\x5f\x73\x61\155\154\137\x77\x68\151\164\x65\154\x69\x73\164\x5f\x64\x6f\155\x61\x69\x6e\163"];
        $I1 = $Mt == 1 ? TRUE : FALSE;
        if (!(MiniorangeSAMLConstants::PLUGIN_VERSION == MiniorangeSAMLConstants::ENTERPRISE_VERSION)) {
            goto mK;
        }
        \Drupal\miniorange_saml\HigherUtilities::saveDomainMapping($rB, $u9, $WG);
        \Drupal\miniorange_saml\HigherUtilities::saveAttributeBasedRestriction($Mr, $aq);
        mK:
        $y8 = \Drupal::configFactory()->getEditable("\x6d\x69\156\x69\157\x72\141\156\147\145\x5f\x73\141\155\x6c\x2e\x73\145\x74\164\x69\x6e\147\163");
        $y8->set("\155\x69\x6e\x69\x6f\162\x61\156\x67\x65\137\x73\141\x6d\154\137\x64\x69\163\x61\x62\x6c\x65\137\141\165\164\157\143\x72\145\x61\x74\145\137\165\163\x65\x72\x73", $Rh)->save();
        $y8->set("\155\x69\x6e\x69\157\x72\141\156\147\145\137\x62\141\143\x6b\x64\157\157\x72\137\x71\165\145\x72\171", $D5)->save();
        $y8->set("\155\151\156\151\x6f\x72\x61\x6e\x67\145\x5f\163\x61\x6d\154\x5f\146\157\162\143\x65\137\141\x75\x74\150", $iL)->save();
        $y8->set("\155\x69\x6e\151\x6f\162\x61\156\147\x65\137\x73\x61\x6d\x6c\137\x61\x75\164\157\137\x72\145\144\x69\x72\x65\x63\x74\137\x74\x6f\x5f\x69\144\x70", $wE)->save();
        $y8->set("\155\x69\x6e\151\x6f\162\141\156\147\x65\x5f\x73\141\155\x6c\x5f\145\156\x61\142\x6c\145\137\142\x61\143\153\x64\157\157\x72", $wS)->save();
        $y8->set("\155\x69\156\151\x6f\162\x61\156\147\145\137\x73\x61\x6d\154\137\x64\x65\x66\141\x75\x6c\164\137\162\x65\154\x61\171\163\164\141\164\x65", $H7)->save();
        $y8->set("\155\151\156\x69\x6f\x72\x61\156\x67\145\x5f\163\141\155\x6c\x5f\154\157\x61\144\x5f\165\163\145\162", $QR)->save();
        $y8->set("\155\x69\156\151\x6f\162\x61\x6e\x67\x65\137\x73\x61\155\x6c\x5f\x72\145\163\164\x72\151\143\x74\x5f\162\x65\x64\x69\x72\x65\x63\164\x5f\x6f\165\164\x73\151\144\x65\x5f\x64\157\155\141\151\156", $I1)->save();
        $y8->set("\x6d\x69\156\x69\x6f\162\x61\x6e\x67\145\137\x73\141\x6d\x6c\x5f\167\x68\151\x74\x65\154\151\x73\x74\137\x64\157\155\x61\151\156\x73", $Mf)->save();
        $y8->set("\155\151\x6e\151\157\x72\x61\x6e\x67\145\137\x73\x61\155\154\137\144\145\146\141\165\x6c\164\x5f\162\145\144\x69\x72\x65\143\164\137\165\162\x6c\x5f\141\146\164\145\x72\x5f\x6c\157\x67\x6f\x75\164", $Bz)->save();
        drupal_flush_all_caches();
        \Drupal::messenger()->addMessage(t("\x53\151\x67\x6e\151\156\x20\x53\145\164\x74\151\156\x67\163\40\163\x75\143\143\x65\163\163\146\x75\154\154\171\x20\163\x61\166\145\144"), "\163\x74\x61\x74\165\163");
    }
}