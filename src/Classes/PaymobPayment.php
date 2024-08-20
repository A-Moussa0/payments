<?php

namespace Nafezly\Payments\Classes;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Nafezly\Payments\Exceptions\MissingPaymentInfoException;
use Nafezly\Payments\Interfaces\PaymentInterface;
use Nafezly\Payments\Classes\BaseController;

class PaymobPayment extends BaseController implements PaymentInterface
{
    private $paymob_api_key;
    private $paymob_integration_id;
    private $paymob_iframe_id;
    private $paymob_hmac_secret;


    public function __construct()
    {
        $this->paymob_api_key = config('nafezly-payments.PAYMOB_API_KEY');
        $this->paymob_integration_id = config('nafezly-payments.PAYMOB_INTEGRATION_ID');
        $this->paymob_iframe_id = config("nafezly-payments.PAYMOB_IFRAME_ID");
        $this->paymob_hmac_secret = config("nafezly-payments.PAYMOB_HMAC_SECRET");
        $this->currency = config("nafezly-payments.PAYMOB_CURRENCY");
    }

    /**
     * @param $amount
     * @param null $user_id
     * @param null $user_first_name
     * @param null $user_last_name
     * @param null $user_email
     * @param null $user_phone
     * @param null $source
     * @return void
     * @throws MissingPaymentInfoException
     */
    public function pay($amount = null, $user_id = null, $user_first_name = null, $user_last_name = null, $user_email = null, $user_phone = null, $source = null)
    {
        $this->setPassedVariablesToGlobal($amount, $user_id, $user_first_name, $user_last_name, $user_email, $user_phone, $source);
        $required_fields = ['amount', 'user_first_name', 'user_last_name', 'user_email', 'user_phone'];
        $this->checkRequiredFields($required_fields, 'PayMob');

        $intention_request = Http::withHeaders(['content-type' => 'application/json'])
            ->post('https://accept.paymob.com/api/acceptance/intention/create', [
                "api_key" => $this->paymob_api_key,
                "amount_cents" => $this->amount * 100,
                "currency" => $this->currency,
                "delivery_needed" => "false",
                "items" => [],
                "shipping_data" => [
                    "apartment" => "NA",
                    "email" => $this->user_email,
                    "floor" => "NA",
                    "first_name" => $this->user_first_name,
                    "street" => "NA",
                    "building" => "NA",
                    "phone_number" => $this->user_phone,
                    "postal_code" => "NA",
                    "city" => "NA",
                    "country" => "NA",
                    "last_name" => $this->user_last_name,
                    "state" => "NA"
                ],
                "billing_data" => [
                    "apartment" => "NA",
                    "email" => $this->user_email,
                    "floor" => "NA",
                    "first_name" => $this->user_first_name,
                    "street" => "NA",
                    "building" => "NA",
                    "phone_number" => $this->user_phone,
                    "postal_code" => "NA",
                    "city" => "NA",
                    "country" => "NA",
                    "last_name" => $this->user_last_name,
                    "state" => "NA"
                ]
            ])->json();

        if (!isset($intention_request['id'])) {
            throw new \Exception('Failed to create payment intention');
        }

        $payment_request = Http::withHeaders(['content-type' => 'application/json'])
            ->post('https://accept.paymob.com/api/acceptance/payment_keys', [
                "auth_token" => $intention_request['token'],
                "amount_cents" => $this->amount * 100,
                "currency" => $this->currency,
                "integration_id" => $this->paymob_integration_id,
                "order_id" => $intention_request['id'],
                "billing_data" => [
                    "apartment" => "NA",
                    "email" => $this->user_email,
                    "floor" => "NA",
                    "first_name" => $this->user_first_name,
                    "street" => "NA",
                    "building" => "NA",
                    "phone_number" => $this->user_phone,
                    "postal_code" => "NA",
                    "city" => "NA",
                    "country" => "NA",
                    "last_name" => $this->user_last_name,
                    "state" => "NA"
                ]
            ])->json();

        if (!isset($payment_request['token'])) {
            throw new \Exception('Failed to create payment key');
        }

        return [
            'payment_id' => $intention_request['id'],
            'html' => "",
            'redirect_url' => "https://accept.paymobsolutions.com/api/acceptance/iframes/" . $this->paymob_iframe_id . "?payment_token=" . $payment_request['token']
        ];
    }

    /**
     * @param Request $request
     * @return array
     */
    public function verify(Request $request): array
    {
        $hmac = $request->header('Hmac');
        $data = $request->all();

        $calculatedHmac = hash_hmac('sha512', json_encode($data), $this->paymob_hmac_secret);

        if (hash_equals($calculatedHmac, $hmac)) {
            if ($data['success'] == true) {
                return [
                    'success' => true,
                    'payment_id' => $data['order']['id'],
                    'message' => __('nafezly::messages.PAYMENT_DONE'),
                    'process_data' => $data
                ];
            } else {
                return [
                    'success' => false,
                    'payment_id' => $data['order']['id'],
                    'message' => __('nafezly::messages.PAYMENT_FAILED_WITH_CODE', ['CODE' => $this->getErrorMessage($data['data']['txn_response_code'])]),
                    'process_data' => $data
                ];
            }
        } else {
            return [
                'success' => false,
                'payment_id' => $data['order']['id'] ?? null,
                'message' => __('nafezly::messages.PAYMENT_FAILED'),
                'process_data' => $data
            ];
        }
    }
    public function getErrorMessage($code){
        $errors=[
            'BLOCKED'=>__('nafezly::messages.Process_Has_Been_Blocked_From_System'),
            'B'=>__('nafezly::messages.Process_Has_Been_Blocked_From_System'),
            '5'=>__('nafezly::messages.Balance_is_not_enough'),
            'F'=>__('nafezly::messages.Your_card_is_not_authorized_with_3D_secure'),
            '7'=>__('nafezly::messages.Incorrect_card_expiration_date'),
            '2'=>__('nafezly::messages.Declined'),
            '6051'=>__('nafezly::messages.Balance_is_not_enough'),
            '637'=>__('nafezly::messages.The_OTP_number_was_entered_incorrectly'),
            '11'=>__('nafezly::messages.Security_checks_are_not_passed_by_the_system'),
        ];
        if(isset($errors[$code]))
            return $errors[$code];
        else
            return __('nafezly::messages.An_error_occurred_while_executing_the_operation');
    }

    public function refund($transaction_id,$amount): array
    {
        $request_new_token = Http::withHeaders(['content-type' => 'application/json'])
            ->post('https://accept.paymobsolutions.com/api/auth/tokens', [
                "api_key" => $this->paymob_api_key
            ])->json();
        $refund_process = Http::withHeaders(['content-type' => 'application/json'])
            ->post('https://accept.paymob.com/api/acceptance/void_refund/refund',['auth_token'=>$request_new_token['token'],'transaction_id'=>$transaction_id,'amount_cents'=>$amount])->json();

        return [
            'transaction_id'=>$transaction_id,
            'amount'=>$amount,
        ];

    }

}