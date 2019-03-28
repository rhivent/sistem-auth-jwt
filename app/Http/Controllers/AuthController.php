<?php

namespace App\Http\Controllers;

use JWTAuth;
use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function signup(Request $request){
		// die('hard!');
		$this->validate($request,[
			'username' => 'required|unique:users',
			'email' => 'required|unique:users',
			'password' => 'required',
		]);
		// dd($request);
		return User::create([
			'username' => $request->json('username'),
			'email' =>  $request->json('email'),
			'password' => bcrypt($request->json('password')),
		]);
	}
	
	public function signin(Request $request){
		$this->validate($request,[
			'username' => 'required','password' => 'required',
		]);
		
		//grap credentials from the request
		$credentials = $request->only('username','password');
		// dd($credentials);
		try{
			//attempt to verify the credentials and create a token for the user
			
			/* pada method json() ada 2 bagian json(['var'=>'value'],status responsnya) 
			untuk referensi pnegertian kode2 status respone 200 ,400, 201, 401, 405,500 dll cek di website
			
			Method attempt ini sudah otomatis mengecek apakah data yg dimasukkan user sama dgn yg ada di DB, jika tidak maka akan ada status 401 (Unauthorized)
			*/
			if(!$token = JWTAuth::attempt($credentials)){
				return response()->json(['error' => 'invalid credentials'],401);
			}
		}catch(JWTException $e){
			//something went wrong whilst attempting to encode the token
			return response()->json(['error' => 'could_not_create_token'],500);
		}
		
		//all good so return the token 
		/* method compact() 
			pengertian nya  ini hanya sekedar memberi JSON dalam btk:
			
			'token' => $token
			
			jadi akan mengambil nama variabel otomatis sesuai dengan nama yg di dlm method compact.
		*/
		// return response()->json(compact('token'));
		return response()->json([
			'user_id' => $request->user()->id,
			'token' => $token
			]);
	}
}
