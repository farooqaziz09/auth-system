<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{

    public function register(Request $request)
    {
        $fields = $request->validate([
            'name' => 'required|string',
            'user_name' => 'required|string|min:4|max:20',
            'email' => 'required|unique:users,email',
            'password' => 'required|string|confirmed',
            'avatar' => 'required|image|mimes:jpeg,png,gif,svg|dimensions:width=256, height=256',
            'user_role' => 'required|string',
        ]);
        $user = User::create([
            'name' => $fields['name'],
            'user_name' => $fields['user_name'],
            'email' => $fields['email'],
            'password' => bcrypt($fields['password']),
            'avatar' => $request->file('avatar')->store('userAvatar'),
            'user_role' => $fields['user_role'],
            'registered_at' => date('Y-m-d H:i:s'),
        ]);

        $token = $user->createToken('myAppToken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token,
        ];
        return response($response, 201);
    }
    public function login(Request $request)
    {
        $fields = $request->validate([
            'email' => 'required',
            'password' => 'required',
        ]);
        $user = User::where('email', $fields['email'])->first();
        if (!$user || !Hash::check($fields['password'], $user->password)) {
            return response([
                'message' => 'Bad Credentials, Please try with correct creds',
            ], 401);
        }
        $token = $user->createToken('myAppToken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token,
        ];
        return response($response, 201);
    }
    public function update(Request $request, $id)
    {
        $user = User::find($id);
     
        $user->update($request->all());
        return $user;
    }
    public function logout()
    {
        auth()->user()->tokens()->delete();
        return [
            'message' => 'Logged Out',
        ];
    }
}
