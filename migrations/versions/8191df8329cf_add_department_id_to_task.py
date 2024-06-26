"""Add department_id to Task

Revision ID: 8191df8329cf
Revises: 97234d7c426f
Create Date: 2024-06-20 01:06:25.368196

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8191df8329cf'
down_revision = '97234d7c426f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('task', schema=None) as batch_op:
        batch_op.alter_column('issued_by',
               existing_type=sa.INTEGER(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('task', schema=None) as batch_op:
        batch_op.alter_column('issued_by',
               existing_type=sa.INTEGER(),
               nullable=False)

    # ### end Alembic commands ###
