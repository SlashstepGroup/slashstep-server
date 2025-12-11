

-- List access policies that the user has access to.
select 
    *
from
    access_policies
WHERE
    can_principal_get_access_policy('User', '019afa5b-9b69-7cd5-8e8e-0b50a13f68f5', NULL, access_policies.*);