CREATE TABLE IF NOT EXISTS items (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  summary TEXT NOT NULL,
  parent_project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  number BIGINT NOT NULL,
  UNIQUE (number, parent_project_id)
);