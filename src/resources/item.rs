pub struct Item {}

impl Item {

  /// Initializes the items table.
  pub fn initialize_items_table(postgres_client: &mut postgres::Client) -> Result<(), postgres::Error> {

    let query = include_str!("../queries/items/initialize-items-table.sql");
    postgres_client.execute(query, &[])?;
    return Ok(());

  }

}