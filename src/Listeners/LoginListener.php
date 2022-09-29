<?php

namespace Rappasoft\LaravelAuthenticationLog\Listeners;

use Illuminate\Auth\Events\Login;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Rappasoft\LaravelAuthenticationLog\Notifications\NewDevice;

class LoginListener
{
    public Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function handle($event): void
    {
        $listener = config('authentication-log.events.login', Login::class);
        if (! $event instanceof $listener) {
            return;
        }

        if ($event->user) {
            $ip = $this->request->ip();

            $ignoreIps = config('authentication-log.ignore_ips');
            if(in_array( $ip, explode(';', $ignoreIps)))
                return;

            $user = $event->user;
            $userAgent = $this->request->userAgent();
            $known = $user->authentications()->whereIpAddress($ip)->whereUserAgent($userAgent)->whereLoginSuccessful(true)->first();
            $newUser = Carbon::parse($user->{$user->getCreatedAtColumn()})->diffInMinutes(Carbon::now()) < 1;

            $log = $user->authentications()->create([
                'ip_address' => $ip,
                'user_agent' => $userAgent,
                'login_at' => now(),
                'login_successful' => true,
                'location' => config('authentication-log.notifications.new-device.location') ? optional(geoip()->getLocation($ip))->toArray() : null,
            ]);

            if (! $known && ! $newUser && config('authentication-log.notifications.new-device.enabled')) {
                $newDevice = config('authentication-log.notifications.new-device.template') ?? NewDevice::class;
                $user->notify(new $newDevice($log));
            }
        }
    }
}
