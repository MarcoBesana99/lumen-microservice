<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }

    public function register() : JsonResponse
	{
		$payload = $this->validate(request(), [
            'name' => 'required|string|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|confirmed|min:8'
        ]);

        try
        {
            $user = new User;
            $user->name = $payload['name'];
            $user->email = $payload['email'];
            $user->password = Hash::make($payload['password']);
            $user->save();

            return response()->json([
                'message' => __('User created'),
                'user' => $user
            ], 201);
        }
        catch (Exception $e)
        {
            return response()->json(['message' => __('User registration failed')], 409);
        }
	}

    public function login() : JsonResponse
    {
        $this->validate(request(), [
            'email' => 'required|string|max:255|email',
            'password' => 'required|string',
        ]);

        $credentials = request()->only(['email', 'password']);

        if (! $token = Auth::attempt($credentials)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }
}
