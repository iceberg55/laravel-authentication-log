<?php

namespace Rappasoft\LaravelAuthenticationLog\Listeners;

use Illuminate\Auth\Events\Failed;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Rappasoft\LaravelAuthenticationLog\Notifications\FailedLogin;

class FailedLoginListener
{
    public Request $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    public function handle($event): void
    {
        $listener = config('authentication-log.events.failed', Failed::class);
        if (! $event instanceof $listener) {
            return;
        }

        if ($event->user) {
            $ip = $this->request->ip();

            $ignoreIps = config('authentication-log.ignore_ips');
            if(in_array( $ip, explode(';', $ignoreIps)))
                return;

            $log = $event->user->authentications()->create([
                'ip_address' => $ip,
                'user_agent' => $this->request->userAgent(),
                'login_at' => now(),
                'login_successful' => false,
                'location' => config('authentication-log.notifications.new-device.location') ? optional(geoip()->getLocation($ip))->toArray() : null,
            ]);

            if (config('authentication-log.notifications.failed-login.enabled')) {
                $failedLogin = config('authentication-log.notifications.failed-login.template') ?? FailedLogin::class;
                $event->user->notify(new $failedLogin($log));
            }
        }
    }
}
