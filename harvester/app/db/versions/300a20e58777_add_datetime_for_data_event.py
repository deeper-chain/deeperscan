"""add datetime for data_event

Revision ID: 300a20e58777
Revises: e627476917aa
Create Date: 2022-01-04 05:36:47.337675

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '300a20e58777'
down_revision = 'e627476917aa'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('data_event', sa.Column('block_datetime', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('data_event', 'block_datetime')
