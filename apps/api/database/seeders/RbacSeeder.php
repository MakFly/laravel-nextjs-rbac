<?php

namespace Database\Seeders;

use App\Models\Permission;
use App\Models\Role;
use App\Models\User;
use Illuminate\Database\Seeder;

class RbacSeeder extends Seeder
{
    public function run(): void
    {
        // Create Roles
        $admin = Role::firstOrCreate(
            ['slug' => 'admin'],
            ['name' => 'Administrator', 'description' => 'Full system access']
        );

        $moderator = Role::firstOrCreate(
            ['slug' => 'moderator'],
            ['name' => 'Moderator', 'description' => 'Content moderation access']
        );

        $user = Role::firstOrCreate(
            ['slug' => 'user'],
            ['name' => 'User', 'description' => 'Standard user access']
        );

        // Create Permissions for resources
        $resources = ['users', 'roles', 'posts', 'comments'];

        foreach ($resources as $resource) {
            Permission::createForResource($resource, ['create', 'read', 'update', 'delete', 'manage']);
        }

        // Assign permissions to Admin (all permissions)
        $admin->permissions()->sync(Permission::all()->pluck('id'));

        // Assign permissions to Moderator
        $moderatorPermissions = Permission::whereIn('resource', ['posts', 'comments'])
            ->whereIn('action', ['read', 'update', 'delete'])
            ->pluck('id');
        $moderatorPermissions = $moderatorPermissions->merge(
            Permission::where('resource', 'users')->where('action', 'read')->pluck('id')
        );
        $moderator->permissions()->sync($moderatorPermissions);

        // Assign permissions to User
        $userPermissions = Permission::whereIn('action', ['read'])
            ->whereIn('resource', ['posts', 'comments'])
            ->pluck('id');
        $userPermissions = $userPermissions->merge(
            Permission::where('resource', 'posts')->where('action', 'create')->pluck('id')
        );
        $userPermissions = $userPermissions->merge(
            Permission::where('resource', 'comments')->where('action', 'create')->pluck('id')
        );
        $user->permissions()->sync($userPermissions);

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

        foreach ($testUsers as $userData) {
            $user = User::firstOrCreate(
                ['email' => $userData['email']],
                [
                    'name' => $userData['name'],
                    'password' => bcrypt('password'),
                    'email_verified_at' => now(),
                ]
            );
            $user->assignRole($userData['role']);
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
