"""Add OTP and email_verified fields

Revision ID: a0798e197c05
Revises: 5ef51e90cb85
Create Date: 2025-01-15 16:54:33.886245

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a0798e197c05'
down_revision = '5ef51e90cb85'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email_verified', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('otp', sa.String(length=150), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('otp')
        batch_op.drop_column('email_verified')

    # ### end Alembic commands ###
