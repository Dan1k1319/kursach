"""Add manager_id to Department

Revision ID: 99fb048b370d
Revises: f07b7fed736b
Create Date: 2024-06-15 06:50:45.011103

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '99fb048b370d'
down_revision = 'f07b7fed736b'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('department', schema=None) as batch_op:
        batch_op.add_column(sa.Column('manager_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_manager_id', 'user', ['manager_id'], ['id'])

def downgrade():
    with op.batch_alter_table('department', schema=None) as batch_op:
        batch_op.drop_constraint('fk_manager_id', type_='foreignkey')
        batch_op.drop_column('manager_id')
