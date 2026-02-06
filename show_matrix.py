"""Показать диагональную матрицу для числовых трансформаций."""
from app.config import settings

# Вывести scale factors
print('=== Scale Factors (диагональ матрицы) ===')
for field, scale in settings.scale_factors.items():
    print(f'  {field}: {scale}')

# Построить диагональную матрицу
fields = list(settings.scale_factors.keys())
scales = list(settings.scale_factors.values())

print('\n=== Диагональная матрица D ===')
print(f'Поля: {fields}\n')
print('       amount   balance   limit')
print(f'      [{scales[0]:.2f}     0.00      0.00 ]')
print(f'  D = [ 0.00     {scales[1]:.2f}      0.00 ]')
print(f'      [ 0.00     0.00      {scales[2]:.2f} ]')

# Пример трансформации
print('\n=== Пример трансформации ===')
original = {'amount': 275.50, 'available_balance': 18350.75, 'credit_limit': 50000.00}
masked = {k: v * settings.scale_factors[k] for k, v in original.items()}

print(f'Original: amount={original["amount"]}, balance={original["available_balance"]}, limit={original["credit_limit"]}')
print(f'Masked:   amount={masked["amount"]:.2f}, balance={masked["available_balance"]:.2f}, limit={masked["credit_limit"]:.2f}')

print('\n=== Обратная матрица D⁻¹ (для unmask) ===')
print(f'amount:   1/{scales[0]} = {1/scales[0]:.4f}')
print(f'balance:  1/{scales[1]} = {1/scales[1]:.4f}')
print(f'limit:    1/{scales[2]} = {1/scales[2]:.4f}')
