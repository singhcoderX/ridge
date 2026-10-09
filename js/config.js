// Public browser configuration only. Never put a Supabase service-role key here.
export const SUPABASE_URL = "https://lgbikgvvurcchxckotwy.supabase.co";
export const SUPABASE_ANON_KEY =
  "sb_publishable_fyem2Lb0pgzB7d9tiIEFIg_SUlcxDEV";
export const TURNSTILE_SITE_KEY = "YOUR_CLOUDFLARE_TURNSTILE_SITE_KEY";

export const isConfigured = () =>
  !SUPABASE_URL.includes("YOUR_PROJECT_REF") &&
  !SUPABASE_ANON_KEY.includes("YOUR_SUPABASE_ANON_KEY");
