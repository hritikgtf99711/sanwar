<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use App\Models\User;
use App\Models\GiftcardUser;
use App\Models\Offer;
use App\Models\AffiliateEarning;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RegisterController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Register Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users as well as their
    | validation and creation. By default this controller uses a trait to
    | provide this functionality without requiring any additional code.
    |
    */

    use RegistersUsers;

    /**
     * Where to redirect users after registration.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;
    //protected $redirectTo = '/';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest:user');
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'first_name' => ['required', 'string', 'max:255'],
            'last_name' => ['required', 'string', 'max:255'],
            'contact' => ['required', 'numeric'/* , 'min:10|max:15' */],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8'],
        ]);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\Models\User
     */
      protected function create(array $data)
    {
        return User::create([
            'first_name' => $data['first_name'],
            'last_name' => $data['last_name'],
            'contact' => $data['contact'],
            'is_staff' => 0,
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'otp'=>$data['otp'],
             'otp_timeStamp'=>$data['otp_expiry'],
             'is_OTP_verified'=>$data['is_verified'],
        ]);
    }

/*
protected function register1(Request $request)
{
    try {
        $validator = Validator::make($request->all(), [
            'first_name' => 'required',
            'last_name' => 'required',
            'email' => 'required|email|unique:users,email',
            'contact' => 'required|numeric|unique:users,contact',
            'password' => ['required', 'string'],
            'country_code' => 'required',
        ], [
            'first_name.required' => 'First name cannot be empty.',
            'last_name.required' => 'Last name cannot be empty.',
            'email.required' => 'Email cannot be empty.',
            'email.unique' => 'Email already exists.',
            'contact.required' => 'Contact number cannot be empty.',
            'contact.numeric' => 'Contact number must contain digits only.',
            'contact.unique' => 'Contact number already exists.',
            'country_code.required' => 'Country code cannot be empty.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'error' => true,
                'message' => $validator->errors()->first()
            ]);
        }

        $otp = rand(100000, 999999);
        $otp_expiry = now()->addMinutes(10); // OTP valid for 10 minutes

        // Prepare data for create method
        $userData = [
            'first_name' => $request->first_name,
            'last_name' => $request->last_name,
            'email' => $request->email,
            'contact' => $request->contact,
            'password' => $request->password, // Will be hashed in create method
            'country_code' => $request->country_code,
            'otp' => $otp,
            'otp_expiry' => $otp_expiry,
            'is_verified' => false,
            'is_staff' => 0 // From the create method
        ];

        // Create user using the create method
        $user = $this->create($userData);

        $mail_data = [
            'otp' => $otp,
            'first_name' => $request->first_name
        ];
        $to_name = $request->first_name;
        $to_email = $request->email;

        try {
            \Mail::send('emails.register_otp', $mail_data, function ($message) use ($to_name, $to_email) {
                $message->to($to_email, $to_name)->subject('Registration OTP');
            });
        } catch (\Exception $e) {
            \Log::error("Email sending failed: " . $e->getMessage());
            // Delete the user if email fails to prevent unverified accounts
            $user->delete();
            return response()->json([
                'error' => true,
                'message' => 'Failed to send email. Please try again.'
            ]);
        }

        return response()->json([
            'error' => false,
            'otp' => $otp,
            'status'=>201,
            'user_id' => $user->id,
            'message' => 'Mail sent successfully. Please verify your account with the OTP.'
        ]);
    } catch (\Exception $e) {
        \Log::error("Registration error: " . $e->getMessage());
        return response()->json([
            'error' =>  $e->getMessage(),
            'message' => 'An error occurred during registration.'
        ]);
    }
}

*/

protected function register1(Request $request)
    {
        try {
            // Validate phone number input
            $validator = Validator::make($request->all(), [
                'contact' => 'required|string|max:20',
                // 'country_code' => 'required|string|max:5',
            ]);
            
            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Validation failed',
                    'errors' => $validator->errors()
                ], 422);
            }

            $fullContact = $request->country_code . $request->contact;

            // Check if user already exists with this contact
            $user = User::where('contact', $request->contact)
                       ->where('country_code', $request->country_code)
                       ->first();

            // Generate 6-digit OTP
            $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);

            if ($user) {
                // Update existing user with new OTP
                $user->update([
                    'otp' => $otpCode,
                    'otp_timeStamp' => now(),
                ]);
            } else {
                // Create minimal user record with just contact and OTP
                $user = User::create([
                    'uuid' => Str::uuid(),
                    'country_code' => $request->country_code,
                    'contact' => $request->contact,
                    'otp' => $otpCode,
                    'is_otp_verified' => false,
                    'otp_timestamp' => now(),
                ]);
            }

            $apiKey = '3cf06612-4f91-11f0-a562-0200cd936042';
            $response = Http::get('https://2factor.in/API/V1/' . $apiKey . '/SMS/' . $fullContact . '/' . $otpCode . '/OTP1'); //api is calling number for otp

            if ($response->failed()) {
                Log::error('2Factor.in API failed', [
                    'contact' => $fullContact,
                    'response' => $response->json()
                ]);
                
                return response()->json([
                    'success' => false,
                    'message' => 'Failed to send OTP',
                    'error' => $response->json()
                ], 500);
            }

            Log::info("OTP Generated and Sent", [
                'contact' => $fullContact,
                'otp' => $otpCode,
                '2factor_response' => $response->json()
            ]);

            return response()->json([
                'success' => true,
                'message' => 'OTP sent to your mobile number successfully.',
                'data' => [
                    'user_id' => $user->id,
                    'contact' => $request->contact,
                    'otp_sent' => true,
                    // For testing only - remove in production
                    'test_otp' => config('app.env') === 'production' ? null : $otpCode
                ]
            ], 200);

        } catch (\Exception $e) {
            Log::error('OTP Generation Failed', [
                'contact' => $fullContact,
                'error' => $e->getMessage()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to send OTP',
                'error' => $e->getMessage()
            ], 500);
        }
    }

/**
 * Verify OTP for user registration
 * @param \Illuminate\Http\Request $request
 * @return \Illuminate\Http\JsonResponse
 */
public function verifyOtp(Request $request) {
    $validator = Validator::make($request->all(), [
        'contact' => 'required|string',
        'otp' => 'required|string|size:6',
    ]);

    if ($validator->fails()) {
        return response()->json([
            'success' => false,
            'errors' => $validator->errors(),
        ], 400);
    }

    $user = User::where('contact', $request->contact)
                ->where('otp', $request->otp)
                ->first();

    if (!$user) {
        return response()->json([
            'success' => false,
            'message' => 'Invalid OTP or contact number.',
        ], 400);
    }

    // Check if OTP is expired
    $otpExpiry = Carbon::parse($user->otp_timestamp)->addMinutes(10);
    if (now()->greaterThan($otpExpiry)) {
        return response()->json([
            'success' => false,
            'message' => 'OTP has expired.',
        ], 400);
    }

    // Mark OTP as verified
    $user->update([
        'is_otp_verified' => true,
        'otp' => null, // Clear OTP after verification
        'otp_timestamp' => null, // Clear OTP timestamp
    ]);

    Auth::guard('user')->login($user); //login user via user guard
    session(['username' => $user->first_name . ' ' . $user->last_name]);

    return response()->json([
        'success' => true,
        'message' => 'OTP verified successfully.',
    ], 200);
}

  public function showVerifyOtpForm($user_id)
    {
        $user = User::findOrFail($user_id);
        return view('auth.verify-otp',compact('user'));
    }
    /**
     * Check OTP validity without consuming it
     */
    public function checkOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'otp' => 'required|string|size:6',
            'type' => 'in:email_verification,password_reset,login',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'errors' => $validator->errors(),
            ], 400);
        }

        $type = $request->input('type', 'email_verification');
        $isValid = $this->otpService->isValidOtp($request->email, $request->otp, $type);

        return response()->json([
            'success' => true,
            'is_valid' => $isValid,
            'remaining_time' => $this->otpService->getRemainingTime($request->email, $type),
        ]);
    }


    /**
     * Resend the OTP to the user.
     *
     * This method handles the process of resending the OTP (One-Time Password)
     * to the user for authentication or verification purposes.
     *
     * @param \Illuminate\Http\Request $request The incoming HTTP request containing necessary data.
     * @return \Illuminate\Http\JsonResponse The response indicating the success or failure of the OTP resend operation.
     */
    public function resendOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'contact' => 'required|string|max:10',  // Adjust max length as needed 
            // 'country_code' => 'required|string|max:5',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::where('contact', $request->contact)->first();

        if (!$user) {
            return response()->json([
                'success' => false,
                'message' => 'User not found.',
            ], 404);
        }

        $lastOtpTimestamp = Carbon::parse($user->otp_timeStamp);
        $currentTimestamp = now();
        $timeDifference = $currentTimestamp->diffInSeconds($lastOtpTimestamp);


        if ($timeDifference < 60) {
            return response()->json([
                'success' => false,
                'message' => 'Please wait before requesting a new OTP.',
                'remaining_time' => 60 - $timeDifference,
            ], 429);
        }

        // Generate new OTP and update user record
        $otpCode = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $user->update([
            'otp' => $otpCode,
            'otp_timestamp' => $currentTimestamp,
        ]);

        $fullContact = $request->country_code . $request->contact;
        $apiKey = 'b0a21695-6309-11f0-a562-0200cd936042';
        // https://2factor.in/API/V1/XXXX-XXXX-XXXX-XXXX-XXXX/SMS/VERIFY3/91XXXXXXXXXX/12345
        $response = Http::get('https://2factor.in/API/V1/' . $apiKey . '/SMS/VERIFY3/' . $fullContact . '/' . $otpCode);

        if ($response->failed()) {
            Log::error('2Factor.in API failed', [
                'contact' => $fullContact,
                'response' => $response->json()
            ]);

            return response()->json([
                'success' => false,
                'message' => 'Failed to send OTP',
                'error' => $response->json()
            ], 500);
        }

        Log::info("OTP Resent", [
            'contact' => $fullContact,
            'otp' => $otpCode,
            '2factor_response' => $response->json()
        ]);

        return response()->json([
            'success' => true,
            'message' => 'OTP sent to your mobile number successfully.',
            'data' => [
                'contact' => $request->contact,
                'otp_sent' => true,
                // For testing only - remove in production
                'test_otp' => config('app.env') === 'production' ? null : $otpCode
            ]
        ], 200);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\Models\User
     */
    protected function register2(Request $request)
    {
        try {
            $request->validate([
                'first_name' => ['required', 'string', 'max:255'],
                'last_name' => ['required', 'string', 'max:255'],
                'contact' => ['required', 'numeric'/* , 'min:10|max:15' */],
                'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
                'password' => ['required', 'string'/* , 'min:8' */],
            ]);
            $input = $request->input();
            $input['password'] = Hash::make($input['password']);
            $input['is_staff'] = 0;
            $input['status'] = 1;
            $user = User::create($input);
            if(\Cache::has('refer_code')){
                //affiliate_wallet
                $refer = User::whereUuid(\Cache::get('refer_code'))->first();
                $referrer_commition = config('aget.REFERRER_COMMISSION_AMOUNT',100);
                $referee_commition = config('aget.REFEREE_COMMISSION_AMOUNT',50);
                $referee_expire = config('aget.REFER_AMOUNT_EXPIRE_DAYS',90);
                AffiliateEarning::create([
                    'expiry_date' => date('Y-m-d',strtotime('+'.$referee_expire.' days')),
                    'amount' => $referrer_commition,
                    'referee_id' => $user->id,
                    'user_id' => $refer->id,
                    'referrer_id' => $refer->id,
                    'created_by'=>$user->id
                ]);
                AffiliateEarning::create([
                    'expiry_date' => date('Y-m-d',strtotime('+'.$referee_expire.' days')),
                    'amount' => $referee_commition,
                    'user_id' => $user->id,
                    'referee_id' => $user->id,
                    'referrer_id' => $refer->id,
                    'created_by'=>$user->id
                ]);
                /* $refer->fill(["affiliate_wallet"=> (($refer->affiliate_wallet ?? 0) + ($referrer_commition ?? 0))])->save();
                $user->fill(["affiliate_wallet"=> ($referee_commition ?? 0)])->save(); */
            }

            $gifts = GiftcardUser::where('reciepient_email', $user->email)->orWhere('reciepient_mobile', $user->contact)->get();
            foreach($gifts AS $gift){
                $oinput['coupon_value'] = $gift->amount;
                $oinput['min_purhcase_value'] = $gift->amount;
                $oinput['max_amount'] = $gift->amount;
                $oinput['max_limit'] = 1;
                $oinput['status'] = 1;
                $oinput['is_user_specific'] = 1;
                $oinput['is_flat'] = 1;
                $oinput['type'] = 'giftcard';
                $oinput['name'] = 'Gift card offer for '.$gift->uuid;
                $oinput['code'] = $gift->uuid;
                $oinput['start_date'] = $gift->created_at->format('Y-m-d');
                $oinput['expiry_date'] = $gift->expiry_date;
                $oinput['created_by'] = $gift->user_id;

                $offer = Offer::create($oinput);

                $offer->users()->sync([$user->id]);
            }
            Auth::guard('user')->loginUsingId($user->id);

            $data = [
                'error' => false,
                'message' => 'Registration successfully.'
            ];
            return response()->json($data);
        }catch (\Exception $e) {
            /**** Exception Error */
            $data = [
                'error' => true,
                'message' => $e->getMessage()
            ];
            return response()->json($data);
        }
    }
}
