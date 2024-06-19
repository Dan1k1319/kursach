"""Add foreign keys with batch mode

Revision ID: bd8602f17639
Revises: 7e73c04807e8
Create Date: 2024-06-19 21:47:58.126106

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bd8602f17639'
down_revision = '7e73c04807e8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('membership',
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('department_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['department_id'], ['department.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('user_id', 'department_id')
    )
    with op.batch_alter_table('department', schema=None) as batch_op:
        batch_op.create_foreign_key(None, 'user', ['manager_id'], ['id'])

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.create_foreign_key(None, 'department', ['department_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')

    with op.batch_alter_table('department', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')

    op.drop_table('membership')
    # ### end Alembic commands ###