class CreateUsers < ActiveRecord::Migration
  def up
  create_table :users do |t|
        t.string :username
        t.string :password
        t.string :salt
        t.string :identifier
        t.timestamps
    end
  end

  def down
    drop_table :users
  end
end
