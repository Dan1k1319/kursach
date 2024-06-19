"""Initial migration

Revision ID: 7e73c04807e8
Revises: 
Create Date: 2024-06-19 21:38:39.079004

"""
# migrations/versions/7e73c04807e8_initial_migration.py

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7e73c04807e8'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'department',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.String(length=255)),
        sa.Column('manager_id', sa.Integer)  # Удалите внешний ключ на данном этапе
    )

    op.create_table(
        'user',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String(length=20), nullable=False, unique=True),
        sa.Column('email', sa.String(length=120), nullable=False, unique=True),
        sa.Column('password', sa.String(length=60), nullable=False),
        sa.Column('bio', sa.String(length=255)),
        sa.Column('passport_data', sa.String(length=255)),
        sa.Column('department_id', sa.Integer),
        sa.Column('position', sa.String(length=100)),
        sa.Column('responsibilities', sa.Text),
        sa.Column('role', sa.String(length=20), nullable=False, default='Employee'),
        sa.Column('phone_number', sa.String(length=20)),
        sa.Column('age', sa.String(length=20)),
        sa.Column('gender', sa.String(length=20)),
        sa.Column('status', sa.String(length=20)),
    )

    op.create_table(
        'task',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('description', sa.String(length=255), nullable=False),
        sa.Column('deadline', sa.DateTime, nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, default='assigned'),
        sa.Column('assigned_to', sa.Integer, sa.ForeignKey('user.id')),
        sa.Column('issued_by', sa.Integer, sa.ForeignKey('user.id')),
        sa.Column('comment', sa.Text),
    )

    op.create_table(
        'rating',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
        sa.Column('score', sa.Float, nullable=False),
    )

    op.create_table(
        'absence',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
        sa.Column('start_date', sa.Date),
        sa.Column('end_date', sa.Date),
        sa.Column('type', sa.String(length=20), nullable=False),
    )

    op.create_table(
        'schedule',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('user.id'), nullable=False),
        sa.Column('day', sa.Date, nullable=False),
    )

def downgrade():
    op.drop_table('schedule')
    op.drop_table('absence')
    op.drop_table('rating')
    op.drop_table('task')
    op.drop_table('user')
    op.drop_table('department')