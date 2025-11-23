create table if not exists users (
  id UUID default uuidv7() primary key,
  username text unique,
  display_name text,
  ip_address inet unique,
  hashed_password text,
  is_anonymous boolean not null default false,
  constraint required_fields check (
    (is_anonymous = true and username is null and display_name is null and hashed_password is null and ip_address is not null)
    or (is_anonymous = false and username is not null and display_name is not null and hashed_password is not null and ip_address is null)
  )
)