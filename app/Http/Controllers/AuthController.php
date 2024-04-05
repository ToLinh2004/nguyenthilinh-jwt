<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Database\Eloquent\Factories\Factory;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    //
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','refresh']]);
    }
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        $data= [
            'random' =>rand().time(),
            'exp' => time() +config('jwt.refresh_ttl')
        ];
       
$refreshToken = JWTAuth::getJWTProvider()->encode($data);
        return $this->respondWithToken($token,$refreshToken);
    }
    public function profile(){
        response()->json(auth('api')->user());
    }
    public function refresh()
    {
       // return $this->respondWithToken(auth('api')->refresh());
    }
    protected function respondWithToken($token, $refreshToken)
    {
        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }
}
