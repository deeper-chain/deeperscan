"""add block_datetime for extrinsic

Revision ID: 61f91ed008b9
Revises: a7c27be741fb
Create Date: 2022-02-24 15:57:39.165842

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '61f91ed008b9'
down_revision = 'a7c27be741fb'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('data_extrinsic', sa.Column('block_datetime', sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('data_extrinsic', 'block_datetime')
    # ### end Alembic commands ###
