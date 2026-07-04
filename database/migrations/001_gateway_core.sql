create table if not exists users (
  id serial primary key,
  subject varchar(255) unique not null,
  username varchar(120) not null,
  email varchar(255),
  roles jsonb not null default '[]'::jsonb,
  provider varchar(40) not null default 'keycloak',
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create table if not exists secret_blobs (
  id varchar(36) primary key,
  owner_subject varchar(255) not null,
  kind varchar(60) not null,
  ciphertext text not null,
  created_at timestamptz not null default now()
);

create table if not exists devices (
  id varchar(36) primary key,
  owner_subject varchar(255) not null,
  name varchar(160) not null,
  kind varchar(40) not null default 'ssh',
  host varchar(255) not null,
  port integer not null default 22,
  username varchar(120) not null,
  auth_type varchar(40) not null default 'password',
  credential_secret_id varchar(36) references secret_blobs(id),
  status varchar(40) not null default 'registered',
  meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists docker_workspaces (
  id varchar(36) primary key,
  owner_subject varchar(255) not null,
  name varchar(160) not null,
  image varchar(255) not null,
  container_name varchar(180) unique not null,
  container_id varchar(255),
  status varchar(40) not null default 'created',
  source_workspace_id varchar(36),
  meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists thin_clients (
  id varchar(36) primary key,
  owner_subject varchar(255) not null,
  hostname varchar(255) not null,
  directory text not null,
  agent_token_hash varchar(128) not null,
  status varchar(40) not null default 'online',
  meta jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create table if not exists oauth_clients (
  client_id varchar(255) primary key,
  client_name varchar(255) not null default 'ChatGPT Connector',
  redirect_uris jsonb not null default '[]'::jsonb,
  scope text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists oauth_codes (
  code varchar(160) primary key,
  client_id varchar(255) not null,
  redirect_uri text not null,
  code_challenge varchar(255) not null,
  scope text not null,
  subject varchar(255) not null,
  expires_at timestamptz not null,
  consumed boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists device_codes (
  device_code varchar(160) primary key,
  user_code varchar(32) unique not null,
  subject varchar(255) not null,
  scope text not null,
  status varchar(40) not null default 'pending',
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists access_grants (
  id varchar(36) primary key,
  owner_subject varchar(255) not null,
  grantee_subject varchar(255) not null,
  resource_type varchar(60) not null,
  resource_id varchar(160) not null,
  scopes jsonb not null default '[]'::jsonb,
  status varchar(40) not null default 'active',
  created_at timestamptz not null default now()
);

create table if not exists audit_events (
  id varchar(36) primary key,
  event_type varchar(120) not null,
  actor_subject varchar(255) not null,
  action varchar(120) not null,
  resource_type varchar(80) not null,
  resource_id varchar(160),
  status varchar(40) not null default 'success',
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
