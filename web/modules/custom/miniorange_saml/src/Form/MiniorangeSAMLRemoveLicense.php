<?php


namespace Drupal\miniorange_saml\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Ajax\HtmlCommand;
use Drupal\Core\Ajax\AjaxResponse;
use Drupal\Core\Ajax\ReplaceCommand;
use Drupal\Core\Ajax\RedirectCommand;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Ajax\OpenModalDialogCommand;
use Drupal\miniorange_saml\AESEncryption;
use Drupal\miniorange_saml\MiniorangeSAMLCustomer;
use Drupal\miniorange_saml\Utilities;
class MiniorangeSAMLRemoveLicense extends FormBase
{
    public function getFormId()
    {
        return "\155\151\156\x69\x6f\x72\141\156\x67\x65\137\163\141\155\154\x5f\x72\145\x6d\157\x76\145\137\154\151\x63\x65\x6e\163\145";
    }
    public function buildForm(array $form, FormStateInterface $form_state, $kk = NULL)
    {
        $form["\x23\160\x72\145\x66\x69\x78"] = "\x3c\x64\x69\x76\40\151\144\75\42\155\157\144\x61\x6c\137\x65\170\141\155\160\154\x65\137\x66\157\x72\x6d\42\x3e";
        $form["\43\x73\x75\x66\x66\x69\170"] = "\x3c\x2f\x64\x69\166\76";
        $form["\163\x74\141\x74\x75\163\x5f\155\145\163\x73\x61\147\x65\x73"] = ["\x23\x74\171\x70\145" => "\163\x74\141\x74\165\x73\x5f\155\x65\x73\x73\x61\147\145\x73", "\x23\167\145\151\147\150\x74" => -10];
        $form["\x6d\x69\x6e\x69\x6f\x72\x61\x6e\147\145\x5f\163\141\x6d\154\x5f\143\x6f\156\x74\x65\x6e\164"] = array("\x23\155\x61\162\153\x75\x70" => "\x41\x72\145\40\171\157\165\x20\x73\165\162\145\40\171\x6f\165\40\x77\x61\x6e\164\40\x74\157\x20\162\x65\155\x6f\166\145\40\164\x68\x65\x20\x4c\151\x63\145\156\x73\x65\x20\x6b\x65\171\x3f\x20\x54\150\145\x20\x63\157\x6e\146\151\147\165\162\x61\x74\151\157\156\163\40\163\x61\x76\x65\x64\x20\167\x69\154\154\40\x6e\x6f\x74\40\142\x65\40\154\157\x73\x74\56");
        $form["\141\143\x74\x69\x6f\x6e\163"] = array("\43\x74\171\160\x65" => "\141\x63\164\151\157\156\x73");
        $form["\141\x63\164\x69\157\x6e\x73"]["\x73\x65\x6e\144"] = ["\x23\x74\x79\x70\145" => "\x73\165\142\x6d\151\x74", "\x23\166\x61\154\x75\145" => $this->t("\x43\x6f\x6e\146\151\x72\155"), "\43\141\164\164\x72\151\x62\165\x74\x65\163" => ["\143\154\x61\x73\163" => ["\165\x73\x65\x2d\141\x6a\141\x78"]], "\43\x61\152\141\170" => ["\143\x61\154\x6c\142\141\143\x6b" => [$this, "\x73\x75\x62\x6d\151\164\x4d\157\x64\x61\154\x46\x6f\x72\155\x41\152\x61\170"], "\x65\166\x65\156\x74" => "\143\154\x69\x63\x6b"]];
        $form["\43\141\x74\x74\141\143\150\x65\x64"]["\x6c\x69\142\162\x61\162\171"][] = "\143\x6f\x72\145\x2f\x64\x72\x75\x70\x61\154\56\144\151\141\154\157\147\56\141\x6a\x61\170";
        return $form;
    }
    public function submitModalFormAjax(array $form, FormStateInterface $form_state)
    {
        $y8 = \Drupal::config("\155\151\156\151\157\162\141\156\x67\x65\x5f\x73\141\x6d\x6c\56\163\145\x74\164\x69\x6e\x67\163");
        $eQ = $y8->get("\x6d\151\156\151\157\x72\x61\156\x67\145\137\163\141\x6d\x6c\x5f\x63\x75\x73\164\x6f\155\145\162\x5f\x61\144\x6d\x69\x6e\x5f\x74\157\x6b\x65\156");
        $d6 = \Drupal::configFactory()->getEditable("\155\x69\x6e\x69\x6f\x72\141\156\x67\x65\137\x73\141\155\154\56\163\145\x74\x74\151\156\147\x73");
        $Z4 = AESEncryption::decrypt_data($d6->get("\x6d\x69\156\157\162\141\156\147\x65\x5f\x73\x61\155\x6c\137\143\x75\x73\x74\x6f\155\145\162\x5f\141\x64\x6d\151\156\x5f\146\162\x61\x75\x64\137\x63\150\x65\143\153"), $eQ);
        $vQ = Utilities::moStoreDomainInDatabase($eQ, 1);
        $DI = new AjaxResponse();
        if ($form_state->hasAnyErrors()) {
            goto SC;
        }
        if (!($y8->get("\x6d\x69\x6e\151\x6f\x72\x61\156\x67\x65\x5f\163\x61\155\x6c\137\154\x69\143\x65\156\x73\145\137\153\x65\x79") != NULL)) {
            goto dR;
        }
        $HC = new MiniorangeSAMLCustomer($y8->get("\155\151\156\x69\x6f\162\141\x6e\x67\x65\137\x73\x61\155\x6c\x5f\143\x75\163\x74\x6f\155\x65\x72\x5f\141\x64\x6d\x69\156\x5f\x65\x6d\141\x69\154"), $y8->get("\155\151\156\151\157\x72\x61\156\147\x65\x5f\x73\x61\155\x6c\137\x63\x75\163\164\x6f\155\x65\162\137\x61\x64\x6d\x69\156\137\160\x68\x6f\x6e\x65"), NULL, NULL);
        if (!($vQ == $Z4)) {
            goto IM;
        }
        $vh = json_decode($HC->updateStatus());
        if (!(!is_object($vh) || !isset($vh->status) || empty($vh->status))) {
            goto mq;
        }
        \Drupal::messenger()->addMessage(t("\105\x72\162\157\x72\x3a\x53\x6f\155\x65\x74\150\x69\156\x67\40\167\145\x6e\x74\x20\x77\162\x6f\x6e\x67\x20\x77\x68\x69\154\145\x20\160\162\x6f\x63\x65\x73\163\151\x6e\147\x20\x79\157\x75\x72\40\162\145\x71\x75\145\x73\164\56\40\x52\x65\x66\x65\x72\x65\156\x63\145\40\x4e\157\56\72\104\70\x53\x53\105\174\x30\x30\x30\71"), "\145\162\x72\157\x72");
        return;
        mq:
        IM:
        $d6->clear("\155\x69\x6e\151\157\x72\141\x6e\x67\145\137\163\141\x6d\154\137\x6c\x69\x63\145\x6e\x73\145\x5f\x6b\x65\171")->save();
        $d6->clear("\155\151\156\151\x6f\162\x61\156\147\x65\137\x73\141\x6d\154\x5f\143\x75\163\x74\157\x6d\145\x72\x5f\x61\144\x6d\151\156\x5f\145\155\141\151\154")->save();
        $d6->clear("\x6d\151\156\x69\157\x72\x61\x6e\x67\145\137\163\x61\155\x6c\x5f\x63\x75\163\x74\x6f\155\x65\162\x5f\141\144\x6d\x69\x6e\137\160\150\157\x6e\x65")->save();
        $d6->clear("\155\x69\156\x69\157\162\141\156\147\x65\x5f\x73\141\x6d\154\x5f\x63\x75\x73\x74\x6f\x6d\145\x72\x5f\141\160\x69\137\x6b\x65\x79")->save();
        $d6->clear("\x6d\x69\x6e\151\x6f\162\x61\x6e\147\145\x5f\163\141\x6d\154\137\x63\165\x73\164\x6f\155\145\x72\x5f\x61\144\x6d\x69\x6e\x5f\164\x6f\x6b\145\156")->save();
        $d6->set("\x6d\151\156\x69\x6f\x72\x61\x6e\147\145\x5f\163\141\x6d\154\x5f\163\164\141\x74\165\163", "\103\125\123\124\x4f\x4d\x45\122\x5f\123\105\x54\x55\120")->save();
        if (empty($d6->get("\155\x69\x6e\151\157\162\141\156\147\145\137\163\141\x6d\x6c\137\154\x69\x63\x65\x6e\163\145\137\x6b\x65\171"))) {
            goto kf;
        }
        \Drupal::messenger()->addMessage(t("\105\x72\x72\x6f\162\x3a\x53\x6f\155\x65\x74\x68\151\x6e\147\x20\167\x65\x6e\164\40\167\162\x6f\x6e\x67\40\x77\150\151\154\145\40\x70\x72\157\x63\x65\163\x73\x69\156\147\40\171\x6f\165\162\x20\x72\145\161\x75\x65\x73\164\56\40\122\x65\x66\145\162\145\156\143\145\40\116\x6f\56\72\104\70\123\x53\105\174\x30\x30\61\x30"), "\145\x72\162\157\x72");
        goto dQ;
        kf:
        \Drupal::messenger()->addMessage(t("\x59\x6f\x75\x72\40\101\x63\x63\157\165\x6e\164\x20\110\141\163\x20\x42\145\x65\156\x20\122\x65\155\x6f\x76\x65\x64\x20\x53\x75\x63\143\x65\163\x73\x66\x75\154\x79\41"), "\x73\x74\x61\x74\165\163");
        dQ:
        dR:
        $DI->addCommand(new RedirectCommand(\Drupal\Core\Url::fromRoute("\x6d\x69\x6e\x69\x6f\x72\x61\x6e\x67\145\137\x73\x61\x6d\154\56\x63\165\x73\x74\x6f\155\145\162\137\x73\x65\x74\x75\160")->toString()));
        goto Ab;
        SC:
        $DI->addCommand(new ReplaceCommand("\x23\155\x6f\144\x61\154\137\145\x78\x61\x6d\160\x6c\x65\137\x66\x6f\x72\x6d", $form));
        Ab:
        return $DI;
    }
    public function validateForm(array &$form, FormStateInterface $form_state)
    {
    }
    public function submitForm(array &$form, FormStateInterface $form_state)
    {
    }
    protected function getEditableConfigNames()
    {
        return ["\143\157\156\x66\x69\147\x2e\155\x69\156\151\x6f\162\141\x6e\x67\145\x5f\x73\141\155\154\137\x72\x65\155\157\x76\145\137\x6c\x69\143\145\156\163\x65"];
    }
}
