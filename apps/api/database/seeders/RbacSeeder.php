<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

class RbacSeeder extends Seeder
{
    public function run(): void
    {
        // Reset cached roles and permissions
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        // Create Permissions for resources
        $resources = ['users', 'roles', 'posts', 'comments'];
        $actions = ['create', 'read', 'update', 'delete', 'manage'];

        foreach ($resources as $resource) {
            foreach ($actions as $action) {
                Permission::firstOrCreate([
                    'name' => "{$resource}.{$action}",
                    'guard_name' => 'api',
                ]);
            }
        }

        // Create Roles
        $admin = Role::firstOrCreate(['name' => 'admin', 'guard_name' => 'api']);
        $moderator = Role::firstOrCreate(['name' => 'moderator', 'guard_name' => 'api']);
        $user = Role::firstOrCreate(['name' => 'user', 'guard_name' => 'api']);

        // Assign permissions to Admin (all permissions)
        $admin->syncPermissions(Permission::where('guard_name', 'api')->get());

        // Assign permissions to Moderator
        $moderatorPermissions = Permission::where('guard_name', 'api')
            ->where(function ($query) {
                $query->whereIn('name', [
                    'posts.read', 'posts.update', 'posts.delete',
                    'comments.read', 'comments.update', 'comments.delete',
                    'users.read',
                ]);
            })
            ->get();
        $moderator->syncPermissions($moderatorPermissions);

        // Assign permissions to User
        $userPermissions = Permission::where('guard_name', 'api')
            ->whereIn('name', [
                'posts.read', 'posts.create',
                'comments.read', 'comments.create',
            ])
            ->get();
        $user->syncPermissions($userPermissions);

        // Create Test Users
        $testUsers = [
            [
                'email' => 'admin@example.com',
                'name' => 'Admin User',
                'role' => 'admin',
            ],
            [
                'email' => 'mod@example.com',
                'name' => 'Mod User',
                'role' => 'moderator',
            ],
            [
                'email' => 'user@example.com',
                'name' => 'Standard User',
                'role' => 'user',
            ],
            [
                'email' => 'john@example.com',
                'name' => 'John Doe',
                'role' => 'user',
            ],
            [
                'email' => 'jane@example.com',
                'name' => 'Jane Smith',
                'role' => 'user',
            ],
        ];

        $roleMap = [
            'admin' => $admin,
            'moderator' => $moderator,
            'user' => $user,
        ];

        foreach ($testUsers as $userData) {
            $testUser = User::firstOrCreate(
                ['email' => $userData['email']],
                [
                    'name' => $userData['name'],
                    'password' => bcrypt('password'),
                    'email_verified_at' => now(),
                ]
            );
            $testUser->assignRole($roleMap[$userData['role']]);
        }

        $this->command->info('RBAC seeding completed!');
        $this->command->info('Test users created (password: "password" for all):');
        $this->command->info('  - admin@example.com (admin)');
        $this->command->info('  - mod@example.com (moderator)');
        $this->command->info('  - user@example.com (user)');
        $this->command->info('  - john@example.com (user)');
        $this->command->info('  - jane@example.com (user)');
    }
}
