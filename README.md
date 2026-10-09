# Ridge

Ridge is a small community chat demo. Vercel serves the static frontend; Supabase provides authentication, persistent shared data, and realtime delivery. The old localStorage/BroadcastChannel backend has been removed.

## Deploy the frontend

1. Push this project to GitHub and import the repository from the Vercel dashboard.
2. Select **Other** as the framework preset, use the repository root, and leave the build command empty so Vercel serves the static files as-is.
3. After deployment, set the Vercel URL as the Supabase Auth Site URL and add it to the allowed redirect URLs.

Vercel hosts only the static files. Supabase provides the app's authentication, database, and realtime services. The project uses a public Supabase client key in the browser; database Row Level Security is what protects user data.

## Configure Supabase

Create a Supabase Free project, then:

1. Run `supabase/migrations/202610090001_initial_schema.sql` in the Supabase SQL Editor.
2. In **Authentication → Providers → Email**, allow new users and turn off email confirmation. Password reset is intentionally not part of v1.
3. In **Authentication → URL Configuration**, set the Site URL to the deployed Vercel URL and add it to the allowed redirect URLs.
4. Put the Supabase project URL and **publishable key** in `js/config.js`.

The Supabase URL and publishable key are public browser values. **Never put the Supabase Secret or service-role key in this repository or frontend.** CAPTCHA is currently disabled in the app. The SQL migration creates the schema, RLS policies, RPC functions, and realtime room policies. Turn on private Realtime channels in the Supabase project's Realtime settings if the project dashboard exposes that setting.

## Features in this hosted v1

- Email/password accounts with public usernames.
- Direct and group text conversations, including end-to-end encrypted chats.
- Persistent messages, realtime delivery, typing and read indicators, message edit/delete, and pins.
- No password reset, email confirmation, polls, attachments, voice notes, or AI features.

Encrypted chat keys are protected by the account password. If a user forgets that password and has no already-unlocked device, their encrypted chats cannot be unlocked.

## Free-tier limits

The site and backend use free plans only. Vercel Hobby is limited to personal, non-commercial use. Supabase can pause an inactive Free project and enforces quotas; reaching a limit can interrupt chat until it resets or the project is restored. Free Supabase projects do not include downloadable database backups. This setup is appropriate for a hackathon demo, not a service with an uptime guarantee.

## Local development

Serve the repository over HTTP so browser JavaScript modules work:

```sh
python3 -m http.server 8000
```

Set `js/config.js` to a Supabase project configured as above, then open `http://localhost:8000/`.
