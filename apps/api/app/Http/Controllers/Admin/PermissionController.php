<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Spatie\Permission\Models\Permission;

class PermissionController extends Controller
{
    public function index(): JsonResponse
    {
        $permissions = Permission::where('guard_name', 'api')
            ->get()
            ->map(function ($perm) {
                $parts = explode('.', $perm->name);
                return [
                    'id' => $perm->id,
                    'name' => $perm->name,
                    'slug' => $perm->name,
                    'resource' => $parts[0] ?? '',
                    'action' => $parts[1] ?? '',
                ];
            });

        return response()->json([
            'data' => $permissions,
        ]);
    }
}
