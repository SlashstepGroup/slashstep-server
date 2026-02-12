CREATE TABLE IF NOT EXISTS item_connections (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  item_connection_type_id UUID NOT NULL REFERENCES item_connection_types(id) ON DELETE CASCADE,
  inward_item_id UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  outward_item_id UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE
);
