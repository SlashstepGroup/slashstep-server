-- The searchable_items view is used to get items based on values of related resources, such as fields and field values.
-- 
-- For example: A user provides the filter "fields.assignee = '00000000-0000-0000-0000-000000000000'". 
-- To create a query that matches this filter, we need to find the field with the name "assignee", 
-- then find the field values that match the provided value, and finally return the items that are related to those field values.
-- In the end, the query will look like look something like this:
-- 
-- SELECT
--     *
-- FROM
--     searchable_items
-- WHERE
--     fields.name = 'assignee' AND field_values.value = '00000000-0000-0000-0000-000000000000';

CREATE OR REPLACE VIEW searchable_items AS
    SELECT DISTINCT
        items.*
    FROM
        items
    LEFT JOIN
        fields ON fields.parent_project_id = items.parent_project_id
    LEFT JOIN
        field_values ON field_values.field_id = fields.id AND (field_values.parent_item_id = items.id OR field_values.parent_resource_type = 'Field');