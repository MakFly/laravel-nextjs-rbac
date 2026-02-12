<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ImpersonationController extends Controller
{
    /**
     * Start impersonating a user
     */
    public function impersonate(Request $request, User $user): JsonResponse
    {
        $admin = $request->user();

        // Cannot impersonate yourself
        if ($admin->id === $user->id) {
            return response()->json([
                'message' => 'You cannot impersonate yourself.',
            ], 403);
        }

        // Cannot impersonate another admin
        if ($user->hasRole('admin')) {
            return response()->json([
                'message' => 'You cannot impersonate an admin user.',
            ], 403);
        }

        // Store the original admin ID in session
        $request->session()->put('impersonator_id', $admin->id);

        // Log in as the target user
        Auth::guard('web')->login($user);

        $userData = AuthController::formatUser($user);
        $userData['is_impersonating'] = true;
        $userData['impersonator'] = [
            'id' => $admin->id,
            'name' => $admin->name,
            'email' => $admin->email,
        ];

        return response()->json([
            'data' => $userData,
            'message' => "Now impersonating {$user->name}",
        ]);
    }

    /**
     * Stop impersonating and return to admin account
     */
    public function stopImpersonating(Request $request): JsonResponse
    {
        $impersonatorId = $request->session()->get('impersonator_id');

        if (!$impersonatorId) {
            return response()->json([
                'message' => 'You are not impersonating anyone.',
            ], 400);
        }

        $admin = User::findOrFail($impersonatorId);

        // Remove impersonation from session
        $request->session()->forget('impersonator_id');

        // Log back in as admin
        Auth::guard('web')->login($admin);

        $userData = AuthController::formatUser($admin);

        return response()->json([
            'data' => $userData,
            'message' => 'Stopped impersonating. Welcome back!',
        ]);
    }
}
